//go:build windows && (amd64 || arm64)

// etw-reader reads an Analytic/Debug channel through eventlog's unified interface.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/tianlin/go-windows-eventlog/pkg/checkpoint"
	"github.com/tianlin/go-windows-eventlog/pkg/eventlog"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	channel := flag.String("channel", "Microsoft-Windows-WMI-Activity/Trace", "Analytic/Debug channel name")
	duration := flag.Duration("duration", 30*time.Second, "capture duration")
	slow := flag.Duration("slow", 0, "optional delay after each batch to exercise queue pressure")
	queue := flag.Int("queue", 1024, "bounded event queue capacity")
	batch := flag.Int("batch", 100, "maximum records per Read")
	ids := flag.String("event-id", "", "event ID filter, e.g. 1,2,3-10,-5")
	level := flag.String("level", "", "exact level filter; empty includes every level")
	describe := flag.Bool("describe", false, "print backend capabilities without starting a session")
	flag.Parse()
	if *duration <= 0 || *slow < 0 {
		return fmt.Errorf("duration must be positive and slow nonnegative")
	}
	reader, err := eventlog.New(eventlog.Config{Name: *channel, ETWQueueSize: *queue, BatchSize: *batch, EventID: *ids, Level: *level})
	if err != nil {
		return err
	}
	defer reader.Close()
	info := json.NewEncoder(os.Stderr)
	caps := reader.(eventlog.CapabilityProvider).Capabilities()
	if err := info.Encode(caps); err != nil {
		return err
	}
	if *describe {
		return nil
	}
	if caps.Backend != "etw" {
		return fmt.Errorf("this capture example requires an Analytic/Debug channel; use examples/eventlog-reader for WinEvt")
	}
	if err := reader.Open(checkpoint.EventLogState{}); err != nil {
		return err
	}
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(signals, *duration)
	defer cancel()
	err = captureEvents(ctx, reader, os.Stdout, *slow)
	if stats, ok := reader.(eventlog.ETWStatsProvider); ok {
		if encodeErr := info.Encode(stats.ETWStats()); encodeErr != nil {
			return errors.Join(err, encodeErr)
		}
	}
	return err
}

type captureReader interface {
	Read() ([]eventlog.Record, error)
	Close() error
}

// A failed Close is not proof that a blocked Read will wake. Report that error
// to main promptly (which retries cleanup on return) instead of waiting forever.
func captureEvents(ctx context.Context, reader captureReader, output io.Writer, slow time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- writeEvents(ctx, reader, output, slow) }()
	select {
	case err := <-done:
		return errors.Join(err, reader.Close())
	case <-ctx.Done():
		if err := reader.Close(); err != nil {
			return err
		}
		return <-done
	}
}

func writeEvents(ctx context.Context, reader captureReader, output io.Writer, slow time.Duration) error {
	encoder := json.NewEncoder(output)
	for {
		records, err := reader.Read()
		for _, r := range records {
			if writeErr := encoder.Encode(r.ToEvent()); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if slow > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(slow):
			}
		}
	}
}
