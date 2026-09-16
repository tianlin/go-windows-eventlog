//go:build windows && (amd64 || arm64)

package eventlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tianlin/go-windows-eventlog/internal/etw"
	"github.com/tianlin/go-windows-eventlog/pkg/checkpoint"
	"golang.org/x/sys/windows"
)

func TestETWQueryKeepsWinEvtRouting(t *testing.T) {
	for _, name := range []string{"query.etl", "Microsoft-Windows-WMI-Activity/Trace"} {
		r, err := New(Config{Name: name, Query: `<QueryList><Query><Select Path="Application">*</Select></Query></QueryList>`})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := r.(*winEventLog); !ok {
			t.Fatalf("query routed to %T", r)
		}
		r.Close()
	}
}

func TestETWDescriptorSurvivesJSON(t *testing.T) {
	l, f := testETWReader(t, Config{})
	if err := l.Open(checkpoint.EventLogState{}); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	f.emit(etw.Event{Provider: windows.GUID{Data1: 123}, Channel: 17, Level: 9, Task: 10, Opcode: 11, Keywords: 12})
	records, err := l.Read()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(records[0].ToEvent().Fields)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	raw := fields["etw"].(map[string]any)
	for k, want := range map[string]float64{"level": 9, "task": 10, "opcode": 11, "keywords": 12} {
		if raw[k] != want {
			t.Errorf("%s: got %v want %v", k, raw[k], want)
		}
	}
}

func TestETWMapSupportsFieldOperations(t *testing.T) {
	props := map[string]any{"Sequence": uint32(42), "Values": []any{uint16(10), uint16(20)}, "Struct": map[string]any{"Count": uint64(1 << 60)}}
	r := Record{ETW: &ETWData{Properties: props, RawData: []byte{1, 2}, Keywords: uint64(1 << 63)}}
	m := r.ToMap()
	for key, want := range map[string]any{"etw.properties.Sequence": uint32(42), "etw.properties.Values": props["Values"], "etw.properties.Struct.Count": uint64(1 << 60), "etw.keywords": uint64(1 << 63)} {
		got, err := m.GetValue(key)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %#v, %v; want %#v", key, got, err, want)
		}
	}
	if got := m.Flatten()["etw.properties.Struct.Count"]; got != uint64(1<<60) {
		t.Errorf("flattened value: %#v", got)
	}
	if err := m.Delete("etw.raw_data"); err != nil {
		t.Error(err)
	}
	if _, err := m.GetValue("etw.raw_data"); err == nil {
		t.Error("raw_data still present")
	}
	if _, err := m.Put("etw.channel_id", uint8(17)); err != nil {
		t.Error(err)
	}
	if got, err := m.GetValue("etw.channel_id"); err != nil || got != uint8(17) {
		t.Fatalf("Put result: %#v, %v", got, err)
	}
}

func TestETWFailedOpenRetainsCleanup(t *testing.T) {
	for _, final := range []bool{false, true} {
		t.Run(fmt.Sprint("final=", final), func(t *testing.T) {
			l, f := testETWReader(t, Config{})
			initErr := errors.New("initialization failed")
			f.closeError = errors.New("stop failed")
			starts := 0
			l.start = func([]etw.Provider, func(etw.Event)) (traceSource, error) { starts++; return f, initErr }
			if err := l.Open(checkpoint.EventLogState{}); !errors.Is(err, initErr) {
				t.Fatal(err)
			}
			if l.run != nil {
				t.Fatal("failed initialization became readable")
			}
			if _, err := l.Read(); err == nil {
				t.Fatal("failed input readable")
			}
			if err := l.Open(checkpoint.EventLogState{}); err == nil || starts != 1 {
				t.Fatal("created another session before cleanup")
			}
			cleanup := l.Reset
			if final {
				cleanup = l.Close
			}
			if err := cleanup(); !errors.Is(err, f.closeError) {
				t.Fatalf("cleanup error: %v", err)
			}
			if err := cleanup(); err != nil {
				t.Fatal(err)
			}
			if f.closeCalls != 2 {
				t.Fatalf("cleanup calls: %d", f.closeCalls)
			}
			if !final {
				l.start = func([]etw.Provider, func(etw.Event)) (traceSource, error) { return nil, initErr }
				if err := l.Open(checkpoint.EventLogState{}); !errors.Is(err, initErr) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestETWRequiresEveryPublisherMapping(t *testing.T) {
	_, err := resolveChannelPublishers("test/Trace", []string{"owner", "importer"}, func(publisher, channel string) ([]channelProvider, error) {
		if publisher == "owner" {
			return []channelProvider{{Name: publisher, Channel: 16}}, nil
		}
		return nil, nil
	})
	if err == nil {
		t.Fatal("accepted incomplete provider mappings")
	}
}

type fakeTrace struct {
	emit       func(etw.Event)
	done       chan struct{}
	closeOnce  sync.Once
	closeCalls int
	closeError error
	runError   error
	stats      etw.Stats
}

func boolPtr(v bool) *bool      { return &v }
func (f *fakeTrace) Run() error { <-f.done; return f.runError }
func (f *fakeTrace) Close() error {
	f.closeCalls++
	f.closeOnce.Do(func() { close(f.done) })
	if f.closeCalls == 1 {
		return f.closeError
	}
	return nil
}
func (f *fakeTrace) Stats() etw.Stats { return f.stats }

func TestETWStatisticsRememberIncompleteHistory(t *testing.T) {
	l, f := testETWReader(t, Config{})
	f.stats = etw.Stats{Error: "final statistics unavailable"}
	if err := l.Open(checkpoint.EventLogState{}); err != nil {
		t.Fatal(err)
	}
	if err := l.Reset(); err != nil {
		t.Fatal(err)
	}
	next := &fakeTrace{done: make(chan struct{})}
	l.start = func(_ []etw.Provider, emit func(etw.Event)) (traceSource, error) { next.emit = emit; return next, nil }
	if err := l.Open(checkpoint.EventLogState{}); err != nil {
		t.Fatal(err)
	}
	if l.ETWStats().StatisticsError == "" {
		t.Error("new session erased incomplete historical statistics")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if l.ETWStats().StatisticsError == "" {
		t.Error("Close erased incomplete historical statistics")
	}
}

func testETWReader(t *testing.T, config Config) (*etwEventLog, *fakeTrace) {
	t.Helper()
	config.Name = "test/Trace"
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	g := windows.GUID{Data1: 123}
	l, err := newETWEventLog(config, []etw.Provider{{GUID: g, Name: "test", Channel: 17}})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTrace{done: make(chan struct{})}
	l.start = func(_ []etw.Provider, emit func(etw.Event)) (traceSource, error) { f.emit = emit; return f, nil }
	return l, f
}

func TestETWRejectsRecovery(t *testing.T) {
	l, _ := testETWReader(t, Config{})
	for _, s := range []checkpoint.EventLogState{{Bookmark: "bookmark"}, {RecordNumber: 1}, {Timestamp: time.Now()}, {Name: "previous"}} {
		if !errors.Is(l.Open(s), ErrETWUnsupported) {
			t.Fatalf("accepted recovery: %+v", s)
		}
	}
}

func TestETWReadKeepsGenerationError(t *testing.T) {
	l, f := testETWReader(t, Config{})
	f.runError = errors.New("old session failed")
	if err := l.Open(checkpoint.EventLogState{}); err != nil {
		t.Fatal(err)
	}
	oldRun := l.run
	if err := l.Reset(); !errors.Is(err, f.runError) {
		t.Fatal(err)
	}
	next := &fakeTrace{done: make(chan struct{})}
	l.start = func(_ []etw.Provider, emit func(etw.Event)) (traceSource, error) { next.emit = emit; return next, nil }
	if err := l.Open(checkpoint.EventLogState{}); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// A Read that captured the previous run must not observe the new run's
	// terminal state after Reset/Open, even if it is scheduled only now.
	if _, err := readETWRun(oldRun, 1); !errors.Is(err, f.runError) {
		t.Fatalf("lost generation error: %v", err)
	}
}

func TestETWResetCountsDiscardedQueue(t *testing.T) {
	l, f := testETWReader(t, Config{})
	if err := l.Open(checkpoint.EventLogState{}); err != nil {
		t.Fatal(err)
	}
	f.emit(etw.Event{Provider: windows.GUID{Data1: 123}, Channel: 17})
	if err := l.Reset(); err != nil {
		t.Fatal(err)
	}
	if st := l.ETWStats(); st.ResetDiscarded != 1 || st.QueueLength != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestETWCloseFailureCanRetry(t *testing.T) {
	l, f := testETWReader(t, Config{})
	f.closeError = errors.New("stop failed")
	if err := l.Open(checkpoint.EventLogState{}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); !errors.Is(err, f.closeError) {
		t.Fatalf("lost close error: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if f.closeCalls != 2 {
		t.Fatalf("failed Close cannot be retried: calls=%d", f.closeCalls)
	}
}

func TestETWResetAndDecodeFailure(t *testing.T) {
	l, f := testETWReader(t, Config{})
	if err := l.Open(checkpoint.EventLogState{}); err != nil {
		t.Fatal(err)
	}
	f.emit(etw.Event{Provider: windows.GUID{Data1: 123}, Channel: 17, ID: 7, DecodeError: "bad payload", RawData: []byte{1}})
	rs, err := l.Read()
	if err != nil || len(rs) != 1 {
		t.Fatalf("%v %v", rs, err)
	}
	if rs[0].ETW.DecodeError != "bad payload" || len(rs[0].ETW.RawData) != 1 || len(rs[0].RenderErr) != 1 {
		t.Fatal("lost partial event")
	}
	if _, ok := rs[0].ToMap()["etw"]; !ok {
		t.Fatal("ToMap lost ETW data")
	}
	if err := l.Reset(); err != nil {
		t.Fatal(err)
	}
	next := &fakeTrace{done: make(chan struct{})}
	l.start = func(_ []etw.Provider, emit func(etw.Event)) (traceSource, error) { next.emit = emit; return next, nil }
	if err := l.Open(checkpoint.EventLogState{}); err != nil {
		t.Fatal(err)
	}
	if st := l.ETWStats(); st.Reopens != 1 || st.DecodeFailures != 1 {
		t.Fatalf("stats %+v", st)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestETWQueueFilterAndClose(t *testing.T) {
	l, f := testETWReader(t, Config{ETWQueueSize: 1, EventID: "7", Level: "verbose"})
	if err := l.Open(checkpoint.EventLogState{}); err != nil {
		t.Fatal(err)
	}
	e := etw.Event{Provider: windows.GUID{Data1: 123}, Channel: 17, ID: 7, Level: 5, Properties: map[string]any{"sequence": uint32(42)}}
	other := e
	other.Channel = 18
	f.emit(other)
	other = e
	other.Provider.Data1 = 456
	f.emit(other)
	other = e
	other.ID = 8
	f.emit(other)
	f.emit(e)
	f.emit(e)
	rs, err := l.Read()
	if err != nil || len(rs) != 1 {
		t.Fatalf("read %v %v", rs, err)
	}
	if rs[0].RecordID != 0 || rs[0].Offset != (checkpoint.EventLogState{}) {
		t.Fatal("fabricated checkpoint")
	}
	if rs[0].ETW.Properties["sequence"] != uint32(42) {
		t.Fatal("lost typed property")
	}
	if l.ETWStats().QueueDropped != 1 {
		t.Fatalf("stats %+v", l.ETWStats())
	}
	done := make(chan error, 1)
	go func() { _, err := l.Read(); done <- err }()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake Read")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Open(checkpoint.EventLogState{}); err == nil {
		t.Fatal("reopened closed reader")
	}
}

func TestETWUnsupportedConfig(t *testing.T) {
	for _, c := range []Config{{Query: "<QueryList/>"}, {IncludeXML: true}, {CheckpointFile: "x"}, {NoMoreEvents: "stop"}, {Locale: 1033}, {Forwarded: boolPtr(true)}} {
		c.Name = "test/Trace"
		c.Validate()
		if _, err := newETWEventLog(c, nil); !errors.Is(err, ErrETWUnsupported) {
			t.Fatalf("config %+v: %v", c, err)
		}
	}
}

func TestETWResolveLocalChannels(t *testing.T) {
	typ, providers, err := resolveETWChannel("Microsoft-Windows-WMI-Activity/Trace")
	if err != nil {
		t.Fatal(err)
	}
	if typ != 2 || len(providers) == 0 {
		t.Fatalf("type=%d providers=%+v", typ, providers)
	}
	t.Logf("resolved providers: %+v", providers)
	r, err := New(Config{Name: "Application"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, ok := r.(*winEventLog); !ok {
		t.Fatalf("ordinary channel routed to %T", r)
	}
	r, err = New(Config{Name: "Microsoft-Windows-WMI-Activity/Trace"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, ok := r.(*etwEventLog); !ok {
		t.Fatalf("analytic channel routed to %T", r)
	}
}
