//go:build windows && (amd64 || arm64)

// Package etw implements the real-time manifest ETW transport.
// All native payloads are copied/decoded before callbacks return.
package etw

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Provider struct {
	GUID    windows.GUID
	Name    string
	Channel uint8
}
type Event struct {
	Provider                              windows.GUID
	ID                                    uint16
	Version, Channel, Level, Opcode       uint8
	Task                                  uint16
	Keywords                              uint64
	PID, TID                              uint32
	Time                                  time.Time
	ActivityID, RelatedActivityID         string
	Properties                            map[string]any
	RawData                               []byte
	MessageTemplate, TaskName, OpcodeName string
	DecodeError                           string
}
type Stats struct {
	EventsLost, RealtimeBuffersLost, BuffersRead uint64
	Error                                        string
}

// Native layouts below follow the 64-bit Windows SDK ABI (evntrace.h,
// evntcons.h). Layout tests guard the critical offsets and sizes.
type traceProperties struct {
	Size, ProviderID                                            uint32
	HistoricalContext, Timestamp                                uint64
	GUID                                                        windows.GUID
	ClientContext, Flags                                        uint32
	BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize uint32
	LogFileMode, FlushTimer, EnableFlags, AgeLimit              uint32
	NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten    uint32
	LogBuffersLost, RealtimeBuffersLost                         uint32
	LoggerThreadID                                              uintptr
	LogFileNameOffset, LoggerNameOffset                         uint32
}
type traceLogfile struct {
	LogFileName, LoggerName        *uint16
	CurrentTime                    int64
	BuffersRead, Mode              uint32
	CurrentEvent                   [88]byte
	LogfileHeader                  [280]byte
	BufferCallback                 uintptr
	BufferSize, Filled, EventsLost uint32
	EventCallback                  uintptr
	IsKernelTrace                  uint32
	Context                        uintptr
}
type descriptor struct {
	ID                              uint16
	Version, Channel, Level, Opcode uint8
	Task                            uint16
	Keywords                        uint64
}
type eventHeader struct {
	Size, HeaderType, Flags, EventProperty uint16
	ThreadID, ProcessID                    uint32
	Timestamp                              uint64
	Provider                               windows.GUID
	Descriptor                             descriptor
	ProcessorTime                          uint64
	Activity                               windows.GUID
}
type eventRecord struct {
	Header                        eventHeader
	BufferContext                 uint32
	ExtendedCount, UserDataLength uint16
	ExtendedData                  *extendedItem
	UserData                      unsafe.Pointer
	Context                       uintptr
}
type extendedItem struct {
	Reserved, Type, Linkage, Size uint16
	Data                          uint64
}

var advapi = windows.NewLazySystemDLL("advapi32.dll")
var startTrace = advapi.NewProc("StartTraceW")
var enableTrace = advapi.NewProc("EnableTraceEx2")
var openTrace = advapi.NewProc("OpenTraceW")
var processTrace = advapi.NewProc("ProcessTrace")
var closeTrace = advapi.NewProc("CloseTrace")
var controlTrace = advapi.NewProc("ControlTraceW")

// Windows callback thunks cannot be freed. Allocate two for the whole process,
// and route via an integer context token, never a Go pointer retained by C.
var sessions sync.Map
var nextID atomic.Uint64
var recordCallback = windows.NewCallback(func(r *eventRecord) uintptr {
	if v, ok := sessions.Load(r.Context); ok {
		v.(*Session).onRecord(r)
	}
	return 0
})
var bufferCallback = windows.NewCallback(func(l *traceLogfile) uintptr {
	if v, ok := sessions.Load(l.Context); ok {
		v.(*Session).buffers.Add(1)
	}
	return 1
})

type Session struct {
	mu               sync.Mutex
	api              traceAPI
	handle, consumer uint64
	name             []uint16
	logfile          traceLogfile
	providers        []Provider
	emit             func(Event)
	token            uintptr
	buffers          atomic.Uint64
	closed           bool
	consumerClosed   bool
	stopped          bool
	started          bool
	initErr          error
	last             Stats
}

func properties(name []uint16) ([]byte, *traceProperties) {
	n := int(unsafe.Sizeof(traceProperties{}))
	b := make([]byte, n+2*len(name))
	p := (*traceProperties)(unsafe.Pointer(&b[0]))
	p.Size = uint32(len(b))
	p.ClientContext = 1
	p.Flags = 0x20000
	p.BufferSize = 64
	p.MinimumBuffers = 4
	p.MaximumBuffers = 64
	p.LogFileMode = 0x100
	p.FlushTimer = 1
	p.LoggerNameOffset = uint32(n)
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&b[n])), len(name)), name)
	return b, p
}

// New may return a non-nil session with an error if initialization rollback
// failed. That session must only be closed (with retries), never run.
func New(providers []Provider, emit func(Event)) (*Session, error) {
	name, err := ownedSessionName()
	if err != nil {
		return nil, err
	}
	return newSession(name, providers, emit, windowsTraceAPI{})
}

func newSession(name []uint16, providers []Provider, emit func(Event), api startupTraceAPI) (*Session, error) {
	s := &Session{api: api, name: name, providers: append([]Provider(nil), providers...), emit: emit, token: uintptr(nextID.Add(1))}
	handle, status := api.start(name)
	if status != 0 {
		return nil, fmt.Errorf("StartTraceW (requires ETW session privileges): %w", windows.Errno(status))
	}
	s.handle = handle
	// Open the consumer before enabling providers so initialization does not
	// discard early events. The owner-qualified name isolates concurrent readers.
	s.logfile = traceLogfile{LoggerName: &s.name[0], Mode: 0x10000100, EventCallback: recordCallback, BufferCallback: bufferCallback, Context: s.token}
	sessions.Store(s.token, s)
	consumer, callErr := api.open(&s.logfile)
	if callErr != nil {
		return s.rollback(fmt.Errorf("OpenTraceW: %w", callErr))
	}
	s.consumer = uint64(consumer)
	seen := map[windows.GUID]bool{}
	for _, provider := range providers {
		if seen[provider.GUID] {
			continue
		}
		seen[provider.GUID] = true
		// Level 0 enables all levels (including custom levels); MatchAnyKeyword=0
		// enables all keywords. Exact filtering follows in the callback/reader.
		status = api.enable(s.handle, provider)
		if status != 0 {
			return s.rollback(fmt.Errorf("EnableTraceEx2 %s: %w", provider.Name, status))
		}
	}
	return s, nil
}

func (s *Session) rollback(err error) (*Session, error) {
	s.initErr = err
	if cleanupErr := s.Close(); cleanupErr != nil {
		return s, errors.Join(err, cleanupErr)
	}
	return nil, err
}

func (s *Session) Run() error {
	s.mu.Lock()
	if s.initErr != nil {
		s.mu.Unlock()
		return fmt.Errorf("ETW initialization failed; only Close is allowed: %w", s.initErr)
	}
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("ETW consumer already started")
	}
	s.started = true
	if s.consumerClosed {
		s.mu.Unlock()
		sessions.Delete(s.token)
		return nil
	}
	s.mu.Unlock()
	defer sessions.Delete(s.token)
	status := s.api.process(s.consumer)
	runtime.KeepAlive(s)
	s.mu.Lock()
	wasClosed := s.consumerClosed
	s.mu.Unlock()
	if wasClosed && (status == windows.ERROR_INVALID_HANDLE || status == windows.ERROR_CANCELLED) {
		return nil
	}
	if status != 0 {
		return fmt.Errorf("ProcessTrace: %w", status)
	}
	return nil
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var stopErr, closeErr error
	// Successful STOP invalidates the controller handle. Never submit it again,
	// even if CloseTrace fails and the caller retries Close.
	if !s.stopped {
		st, code := s.api.control(s.handle, s.name, 1)
		switch code {
		case 0:
			s.stopped = true
			s.last = st
		case windows.ERROR_MORE_DATA:
			s.stopped = true
			s.last = st
			s.last.Error = "ControlTrace STOP returned incomplete statistics"
		case windows.ERROR_WMI_INSTANCE_NOT_FOUND:
			s.stopped = true
			s.last.Error = "session stopped externally; final statistics unavailable"
		default:
			stopErr = fmt.Errorf("ControlTrace STOP: %w", code)
			s.last.Error = stopErr.Error()
		}
	}
	if s.consumer != 0 && !s.consumerClosed {
		code := s.api.close(s.consumer)
		if code != 0 && code != windows.ERROR_CTX_CLOSE_PENDING {
			closeErr = fmt.Errorf("CloseTrace: %w", code)
		} else {
			s.consumerClosed = true
		}
	}
	if !s.started && (s.consumer == 0 || s.consumerClosed) {
		sessions.Delete(s.token)
	}
	s.closed = s.stopped && closeErr == nil
	return errors.Join(stopErr, closeErr)
}

func (s *Session) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.stopped {
		st, code := s.api.control(s.handle, s.name, 0)
		if code == 0 {
			s.last = st
		} else {
			s.last.Error = fmt.Sprintf("ControlTrace QUERY: %v", code)
		}
	}
	st := s.last
	st.BuffersRead = s.buffers.Load()
	return st
}
func (s *Session) onRecord(r *eventRecord) {
	h := r.Header
	d := h.Descriptor
	matched := false
	for _, p := range s.providers {
		if p.GUID == h.Provider && p.Channel == d.Channel {
			matched = true
			break
		}
	}
	if !matched {
		return
	}
	e := Event{Provider: h.Provider, ID: d.ID, Version: d.Version, Channel: d.Channel, Level: d.Level, Opcode: d.Opcode, Task: d.Task, Keywords: d.Keywords, PID: h.ProcessID, TID: h.ThreadID,
		Time: time.Unix(int64(h.Timestamp/10000000)-11644473600, int64(h.Timestamp%10000000)*100).UTC()}
	if h.Activity != (windows.GUID{}) {
		e.ActivityID = h.Activity.String()
	}
	if r.ExtendedData != nil {
		for _, x := range unsafe.Slice(r.ExtendedData, int(r.ExtendedCount)) {
			if x.Type == 1 && x.Size == 16 && x.Data != 0 {
				// DataPtr is a native pointer represented as ULONGLONG by the SDK.
				p := *(*unsafe.Pointer)(unsafe.Pointer(&x.Data))
				e.RelatedActivityID = (*windows.GUID)(p).String()
			}
		}
	}
	if r.UserData != nil && r.UserDataLength > 0 {
		e.RawData = append([]byte(nil), unsafe.Slice((*byte)(r.UserData), int(r.UserDataLength))...)
	}
	if err := decodeEvent(r, &e); err != nil {
		e.DecodeError = err.Error()
	}
	s.emit(e)
}
