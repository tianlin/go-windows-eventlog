//go:build windows && (amd64 || arm64)

package etw

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func loadTestManifest(t *testing.T) windows.GUID {
	t.Helper()
	path, err := filepath.Abs("testdata/poc.man")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(path)
	code, _, _ := tdh.NewProc("TdhLoadManifest").Call(uintptr(unsafe.Pointer(p)))
	if code != 0 {
		t.Fatalf("TdhLoadManifest: %v", windows.Errno(code))
	}
	t.Cleanup(func() { tdh.NewProc("TdhUnloadManifest").Call(uintptr(unsafe.Pointer(p))) })
	guid, _ := windows.GUIDFromString("{25DC572A-3502-43E3-AEC1-32C05E130C81}")
	return guid
}

func fixturePayload(seq uint32) []byte {
	b := []byte{0, 0, 0, 0, 'h', 0, 'i', 0, 0, 0, 2, 0, 10, 0, 0, 0, 20, 0, 0, 0}
	binary.LittleEndian.PutUint32(b, seq)
	return b
}

func TestTDHManifestDecode(t *testing.T) {
	guid := loadTestManifest(t)
	payload := fixturePayload(42)
	r := eventRecord{Header: eventHeader{Size: 80, Provider: guid, Descriptor: descriptor{ID: 1, Channel: 16, Level: 5, Task: 1}}, UserDataLength: uint16(len(payload)), UserData: unsafe.Pointer(&payload[0])}
	e := Event{RawData: append([]byte(nil), payload...)}
	if err := decodeEvent(&r, &e); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"Sequence": uint32(42), "Text": "hi", "Count": uint16(2), "Values": []any{uint32(10), uint32(20)}}
	if e.TaskName != "FixtureTask" {
		t.Fatalf("decoded task = %q, want FixtureTask", e.TaskName)
	}
	if !reflect.DeepEqual(e.Properties, want) {
		t.Fatalf("got %#v want %#v", e.Properties, want)
	}
	payload[0] = 0
	if e.Properties["Sequence"] != uint32(42) {
		t.Fatal("decoded event retained native data")
	}
	r.UserDataLength = 1
	if err := decodeEvent(&r, &Event{}); err == nil {
		t.Fatal("truncated payload decoded successfully")
	}
	runtime.KeepAlive(payload)
}

// This test creates only its own owner-qualified session and registers an
// in-process fixture provider. TdhLoadManifest is process-local; no system
// channel is installed, enabled, disabled or removed.
func TestNativeRealtimeSequence(t *testing.T) {
	if os.Getenv("ETW_INTEGRATION") != "1" {
		t.Skip("set ETW_INTEGRATION=1 in an elevated shell")
	}
	guid := loadTestManifest(t)
	events := make(chan Event, 32)
	s, err := New([]Provider{{GUID: guid, Channel: 16, Name: "PoC"}}, func(e Event) { events <- e })
	if s != nil {
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var runErr error
	go func() { runErr = s.Run(); close(done) }()
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
		select {
		case <-done:
			if runErr != nil {
				t.Error(runErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("ProcessTrace failed to stop")
		}
	})
	var provider uint64
	code, _, _ := advapi.NewProc("EventRegister").Call(uintptr(unsafe.Pointer(&guid)), 0, 0, uintptr(unsafe.Pointer(&provider)))
	if code != 0 {
		t.Fatal(windows.Errno(code))
	}
	defer advapi.NewProc("EventUnregister").Call(uintptr(provider))
	type dataDescriptor struct {
		Ptr            uint64
		Size, Reserved uint32
	}
	for seq := uint32(0); seq < 10; seq++ {
		b := fixturePayload(seq)
		data := dataDescriptor{Ptr: uint64(uintptr(unsafe.Pointer(&b[0]))), Size: uint32(len(b))}
		for _, channel := range []uint8{16, 17} {
			d := descriptor{ID: uint16(channel - 15), Channel: channel, Level: 5, Task: 1}
			code, _, _ = advapi.NewProc("EventWrite").Call(uintptr(provider), uintptr(unsafe.Pointer(&d)), 1, uintptr(unsafe.Pointer(&data)))
			if code != 0 {
				t.Fatal(windows.Errno(code))
			}
		}
		runtime.KeepAlive(b)
	}
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	seen := map[uint32]bool{}
	for len(seen) < 10 {
		select {
		case e := <-events:
			if e.Channel != 16 || e.DecodeError != "" {
				t.Fatalf("wrong channel or decode failure: %+v", e)
			}
			seq, ok := e.Properties["Sequence"].(uint32)
			if !ok || seq >= 10 || seen[seq] {
				t.Fatalf("invalid/duplicate sequence: %+v", e)
			}
			seen[seq] = true
		case <-timer.C:
			t.Fatalf("received %d/10 sequences", len(seen))
		}
	}
	// Closing and draining detects duplicates/other channels arriving after
	// the tenth expected event, not only those interleaved with it.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("consumer did not stop")
	}
	if len(events) != 0 {
		t.Fatalf("unexpected events after expected sequences: %d", len(events))
	}
}

func TestNativePermissionOrCleanClose(t *testing.T) {
	guid, _ := windows.GenerateGUID()
	s, err := New([]Provider{{GUID: guid, Channel: 16}}, func(Event) {})
	if s != nil {
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Log("non-elevated session correctly reports access denied")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Run() }()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not stop ProcessTrace")
	}
}

func TestWindowsABI(t *testing.T) {
	for name, pair := range map[string][2]uintptr{
		"EVENT_TRACE_PROPERTIES": {unsafe.Sizeof(traceProperties{}), 120},
		"EVENT_TRACE_LOGFILEW":   {unsafe.Sizeof(traceLogfile{}), 448},
		"EVENT_RECORD":           {unsafe.Sizeof(eventRecord{}), 112},
		"EventRecordCallback":    {unsafe.Offsetof(traceLogfile{}.EventCallback), 424},
		"Context":                {unsafe.Offsetof(traceLogfile{}.Context), 440},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: got %d want %d", name, pair[0], pair[1])
		}
	}
}

func TestNativeControlByName(t *testing.T) {
	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16FromString("go-eventlog-absent-" + guid.String())
	if err != nil {
		t.Fatal(err)
	}
	// Query a unique nonexistent session: a supplied name reaches session lookup,
	// while a zero handle and NULL name are rejected as invalid parameters.
	_, code := (windowsTraceAPI{}).control(0, name, 0)
	if code != windows.ERROR_WMI_INSTANCE_NOT_FOUND {
		t.Fatalf("named query: got %v, want ERROR_WMI_INSTANCE_NOT_FOUND", code)
	}
}

func TestDecodeValues(t *testing.T) {
	for _, tt := range []struct {
		typ  uint16
		b    []byte
		want any
	}{{8, []byte{42, 0, 0, 0}, uint32(42)}, {1, []byte{'h', 0, 'i', 0, 0, 0}, "hi"}, {13, []byte{1, 0, 0, 0}, true}} {
		got, err := decodeValue(tt.typ, tt.b)
		if err != nil || got != tt.want {
			t.Fatalf("got %v err=%v want %v", got, err, tt.want)
		}
	}
	if _, err := decodeValue(8, []byte{1}); err == nil {
		t.Fatal("accepted truncated uint32")
	}
}
