//go:build windows && (amd64 || arm64)

package eventlog

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/tianlin/go-windows-eventlog/internal/etw"
	"github.com/tianlin/go-windows-eventlog/pkg/checkpoint"
	"github.com/tianlin/go-windows-eventlog/pkg/winevent"
)

type traceSource interface {
	Run() error
	Close() error
	Stats() etw.Stats
}

// Each Read captures one generation. Its terminal error is published before
// queue closes, so Reset/Open cannot replace an older blocked Read's result.
type etwRun struct {
	source traceSource
	queue  chan Record
	done   chan struct{}
	err    error
}
type etwEventLog struct {
	lifecycle                         sync.Mutex
	mu                                sync.Mutex
	config                            Config
	providers                         []etw.Provider
	filter                            *recordFilter
	start                             func([]etw.Provider, func(etw.Event)) (traceSource, error)
	run                               *etwRun
	cleanupPending                    traceSource
	resetDiscarded                    uint64
	closed                            bool
	opens                             uint64
	received, dropped, decodeFailures atomic.Uint64
	previous                          etw.Stats
}

func newChannelETWReader(c Config, p []channelProvider) (EventLog, error) {
	providers := make([]etw.Provider, len(p))
	for i, v := range p {
		providers[i] = etw.Provider{GUID: v.GUID, Name: v.Name, Channel: v.Channel}
	}
	return newETWEventLog(c, providers)
}
func newETWEventLog(c Config, p []etw.Provider) (*etwEventLog, error) {
	if c.Query != "" || c.IncludeXML || c.CheckpointFile != "" || c.Locale != 0 || c.Forwarded != nil || (c.NoMoreEvents != "" && c.NoMoreEvents != "wait") {
		return nil, fmt.Errorf("%w: Query, IncludeXML, CheckpointFile, Locale, Forwarded and NoMoreEvents other than wait are not supported", ErrETWUnsupported)
	}
	f, err := newRecordFilter(c.recordQuery())
	if err != nil {
		return nil, err
	}
	if c.ETWQueueSize == 0 {
		c.ETWQueueSize = 1024
	}
	return &etwEventLog{config: c, providers: p, filter: f, start: func(p []etw.Provider, emit func(etw.Event)) (traceSource, error) {
		s, err := etw.New(p, emit)
		if s == nil {
			return nil, err
		}
		return s, err
	}}, nil
}

func (l *etwEventLog) Name() string {
	if l.config.ID != "" {
		return l.config.ID
	}
	return l.config.Name
}
func (l *etwEventLog) Channel() string { return l.config.Name }
func (l *etwEventLog) IsFile() bool    { return false }
func (l *etwEventLog) Capabilities() Capabilities {
	return Capabilities{Backend: "etw", RealtimeOnly: true}
}

func (l *etwEventLog) Open(state checkpoint.EventLogState) error {
	l.lifecycle.Lock()
	defer l.lifecycle.Unlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if state != (checkpoint.EventLogState{}) {
		return fmt.Errorf("%w: nonempty recovery state", ErrETWUnsupported)
	}
	if l.closed {
		return fmt.Errorf("ETW reader is closed")
	}
	if l.run != nil {
		return fmt.Errorf("ETW reader already open; Reset before Open")
	}
	if l.cleanupPending != nil {
		return fmt.Errorf("ETW initialization cleanup pending; retry Reset or Close before Open")
	}
	q := make(chan Record, l.config.ETWQueueSize)
	source, err := l.start(l.providers, func(e etw.Event) { l.accept(q, e) })
	if err != nil {
		l.cleanupPending = source
		return err
	}
	run := &etwRun{source: source, queue: q, done: make(chan struct{})}
	l.run = run
	l.opens++
	go func() {
		run.err = source.Run()
		close(q)
		close(run.done)
	}()
	return nil
}

func (l *etwEventLog) accept(q chan Record, e etw.Event) {
	var name string
	for _, p := range l.providers {
		if p.GUID == e.Provider && p.Channel == e.Channel {
			name = p.Name
			break
		}
	}
	if name == "" {
		return
	}
	l.received.Add(1)
	opcode := e.Opcode
	r := Record{
		Event: winevent.Event{
			Provider:        winevent.Provider{Name: name, GUID: e.Provider.String()},
			EventIdentifier: winevent.EventIdentifier{ID: uint32(e.ID)},
			Version:         winevent.Version(e.Version),
			LevelRaw:        e.Level, TaskRaw: e.Task, OpcodeRaw: &opcode, KeywordsRaw: winevent.HexInt64(e.Keywords),
			TimeCreated: winevent.TimeCreated{SystemTime: e.Time},
			Channel:     l.config.Name, Task: e.TaskName, Opcode: e.OpcodeName,
			Correlation: winevent.Correlation{ActivityID: e.ActivityID, RelatedActivityID: e.RelatedActivityID},
			Execution:   winevent.Execution{ProcessID: e.PID, ThreadID: e.TID},
		},
		ETW: &ETWData{
			ChannelID: e.Channel, Level: e.Level, Task: e.Task, Opcode: e.Opcode, Keywords: e.Keywords,
			Properties: e.Properties, RawData: e.RawData,
			MessageTemplate: e.MessageTemplate, DecodeError: e.DecodeError,
		},
	}
	levels := []string{"LogAlways", "Critical", "Error", "Warning", "Information", "Verbose"}
	if int(e.Level) < len(levels) {
		r.Level = levels[e.Level]
	}
	if e.DecodeError != "" {
		l.decodeFailures.Add(1)
		r.RenderErr = []string{e.DecodeError}
	}
	if !l.filter.match(&r) {
		return
	}
	select {
	case q <- r:
	default:
		l.dropped.Add(1)
	}
}

func (l *etwEventLog) Read() ([]Record, error) {
	l.mu.Lock()
	run, closed := l.run, l.closed
	l.mu.Unlock()
	if run == nil {
		if closed {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("ETW reader is not open")
	}
	return readETWRun(run, l.config.BatchSize)
}

func readETWRun(run *etwRun, maxRead int) ([]Record, error) {
	q := run.queue
	first, ok := <-q
	if !ok {
		err := run.err
		if err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	batch := []Record{first}
	for len(batch) < maxRead {
		select {
		case r, ok := <-q:
			if !ok {
				return batch, nil
			}
			batch = append(batch, r)
		default:
			return batch, nil
		}
	}
	return batch, nil
}

// shutdown serializes lifecycle changes, releases mu while waiting for the
// consumer, and retains a successfully closed generation for queued reads.
func (l *etwEventLog) shutdown(final bool) error {
	l.lifecycle.Lock()
	defer l.lifecycle.Unlock()
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	if l.cleanupPending != nil {
		if err := l.cleanupPending.Close(); err != nil {
			l.mu.Unlock()
			return err
		}
		l.cleanupPending = nil
	}
	run := l.run
	if run == nil {
		if final {
			l.closed = true
		}
		l.mu.Unlock()
		return nil
	}
	err := run.source.Close()
	if err != nil {
		// Retain the session so callers can retry cleanup. A failed native
		// close is not proof that ProcessTrace has exited; never wait here.
		l.mu.Unlock()
		return err
	}
	l.mu.Unlock()
	<-run.done
	l.mu.Lock()
	defer l.mu.Unlock()
	if final {
		l.closed = true
	}
	if l.run == run {
		st := run.source.Stats()
		l.previous.EventsLost += st.EventsLost
		l.previous.RealtimeBuffersLost += st.RealtimeBuffersLost
		l.previous.BuffersRead += st.BuffersRead
		if st.Error != "" {
			l.previous.Error = "historical loss statistics are incomplete: " + st.Error
		}
		if !final {
			// Drain only records not already taken by a concurrent Read.
			for range run.queue {
				l.resetDiscarded++
			}
			l.run = nil
		}
	}
	return errors.Join(err, run.err)
}
func (l *etwEventLog) Close() error { return l.shutdown(true) }
func (l *etwEventLog) Reset() error { return l.shutdown(false) }
func (l *etwEventLog) ETWStats() ETWStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.previous
	queueLength := 0
	if l.run != nil {
		queueLength = len(l.run.queue)
	}
	if l.run != nil && !l.closed {
		n := l.run.source.Stats()
		st.EventsLost += n.EventsLost
		st.RealtimeBuffersLost += n.RealtimeBuffersLost
		st.BuffersRead += n.BuffersRead
		if n.Error != "" {
			if st.Error != "" {
				st.Error += "; "
			}
			st.Error += n.Error
		}
	}
	reopens := uint64(0)
	if l.opens > 0 {
		reopens = l.opens - 1
	}
	return ETWStats{Received: l.received.Load(), QueueDropped: l.dropped.Load(), ResetDiscarded: l.resetDiscarded, DecodeFailures: l.decodeFailures.Load(), Reopens: reopens, EventsLost: st.EventsLost, RealtimeBuffersLost: st.RealtimeBuffersLost, BuffersRead: st.BuffersRead, QueueLength: queueLength, StatisticsError: st.Error}
}

var _ EventLog = (*etwEventLog)(nil)
