//go:build windows && (amd64 || arm64)

package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tianlin/go-windows-eventlog/pkg/eventlog"
)

type failedCloser struct {
	release chan struct{}
	failure error
}

func (f *failedCloser) Read() ([]eventlog.Record, error) { <-f.release; return nil, io.EOF }
func (f *failedCloser) Close() error                     { return f.failure }

func TestCaptureReportsCloseFailureWithoutWaitingForRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &failedCloser{release: make(chan struct{}), failure: errors.New("CloseTrace failed")}
	defer close(r.release)
	done := make(chan error, 1)
	go func() { done <- captureEvents(ctx, r, io.Discard, 0) }()
	select {
	case err := <-done:
		if !errors.Is(err, r.failure) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("capture hung after cleanup failure")
	}
}
