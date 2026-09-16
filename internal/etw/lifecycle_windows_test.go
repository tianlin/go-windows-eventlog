//go:build windows && (amd64 || arm64)

package etw

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

type fakeTraceAPI struct {
	stops, closes         int
	stopError, closeError windows.Errno
}

func (a *fakeTraceAPI) control(_ uint64, _ []uint16, op uint32) (Stats, windows.Errno) {
	if op == 1 {
		a.stops++
		return Stats{EventsLost: 7}, a.stopError
	}
	return Stats{EventsLost: 3}, 0
}
func (a *fakeTraceAPI) close(uint64) windows.Errno {
	a.closes++
	if a.closes == 1 {
		return a.closeError
	}
	return 0
}
func (a *fakeTraceAPI) process(uint64) windows.Errno { return 0 }

func TestSessionCloseRetriesOnlyLiveHandles(t *testing.T) {
	api := &fakeTraceAPI{closeError: windows.ERROR_BUSY}
	s := &Session{api: api, handle: 1, consumer: 2}
	if err := s.Close(); !errors.Is(err, windows.ERROR_BUSY) {
		t.Fatalf("lost native error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if api.stops != 1 || api.closes != 2 {
		t.Fatalf("stops=%d closes=%d", api.stops, api.closes)
	}
	if st := s.Stats(); st.EventsLost != 7 {
		t.Fatalf("lost final counters: %+v", st)
	}
}

func TestSessionStopFailurePreservesErrno(t *testing.T) {
	api := &fakeTraceAPI{stopError: windows.ERROR_ACCESS_DENIED}
	s := &Session{api: api, handle: 1, consumer: 2}
	if err := s.Close(); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("lost stop error: %v", err)
	}
	api.stopError = 0
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if api.stops != 2 || api.closes != 1 {
		t.Fatalf("stops=%d closes=%d", api.stops, api.closes)
	}
}

func TestSessionCloseBeforeRunReleasesContext(t *testing.T) {
	s := &Session{api: &fakeTraceAPI{}, handle: 1, consumer: 2, token: uintptr(nextID.Add(1))}
	sessions.Store(s.token, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := sessions.Load(s.token); ok {
		t.Fatal("callback context leaked")
	}
	if err := s.Run(); err != nil {
		t.Fatal(err)
	}
}
