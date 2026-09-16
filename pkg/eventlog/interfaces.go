// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Package eventlog provides a high-level API for reading Windows Event Logs.
package eventlog

import (
	"github.com/tianlin/go-windows-eventlog/pkg/checkpoint"
)

// EventLog is an interface to a Windows Event Log.
// This interface provides a simple abstraction over the underlying Windows Event Log API.
type EventLog interface {
	// Open the event log. state points to the last successfully read event
	// in this event log. Read will resume from the next record. To start reading
	// from the first event specify a zero-valued EventLogState.
	// Real-time ETW requires zero state and starts with future events only;
	// use CapabilityProvider to discover source-specific recovery semantics.
	Open(state checkpoint.EventLogState) error

	// Read records from the event log. Returns a slice of records or an error.
	// If io.EOF is returned you should stop reading and close the log.
	Read() ([]Record, error)

	// Reset closes the event log channel to allow recovering from recoverable
	// errors. Open must be successfully called after a Reset before Read may
	// be called.
	Reset() error

	// Close the event log. It should not be re-opened after closing.
	Close() error

	// Name returns the event log's name.
	Name() string

	// Channel returns the event log's channel name.
	Channel() string

	// IsFile returns true if the event log is an evtx file.
	IsFile() bool
}

// CheckpointProvider is an optional EventLog extension that exposes the
// latest source position reached by the reader. This position advances when
// the reader accepts a record, including a record skipped during recovery. It
// is separate from any durable checkpoint maintained by the caller after
// successful delivery.
type CheckpointProvider interface {
	Checkpoint() checkpoint.EventLogState
}

// Publisher is an interface for publishing events read from the event log.
// Implementations should handle batching, error handling, and any required
// transformations.
type Publisher interface {
	// Publish publishes a batch of records. Returns an error if publishing fails.
	Publish(records []Record) error
}

// StatusReporter is an interface for reporting the status of event log reading.
// This allows consumers to monitor the health and progress of event log reading.
type StatusReporter interface {
	// UpdateStatus updates the current status with a descriptive message.
	UpdateStatus(status Status, message string)
}

// Status represents the current state of the event log reader.
type Status int

const (
	// StatusStarting indicates the reader is initializing.
	StatusStarting Status = iota
	// StatusRunning indicates the reader is actively reading events.
	StatusRunning
	// StatusDegraded indicates the reader encountered recoverable errors.
	StatusDegraded
	// StatusFailed indicates the reader encountered unrecoverable errors.
	StatusFailed
	// StatusStopped indicates the reader has stopped.
	StatusStopped
)

// String returns the string representation of the Status.
func (s Status) String() string {
	switch s {
	case StatusStarting:
		return "starting"
	case StatusRunning:
		return "running"
	case StatusDegraded:
		return "degraded"
	case StatusFailed:
		return "failed"
	case StatusStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// Logger is a simple logging interface that can be implemented by any logging library.
// This allows the library to be agnostic to the specific logging implementation.
type Logger interface {
	// Debug logs a debug message with optional key-value pairs.
	Debug(msg string, keysAndValues ...interface{})
	// Info logs an info message with optional key-value pairs.
	Info(msg string, keysAndValues ...interface{})
	// Warn logs a warning message with optional key-value pairs.
	Warn(msg string, keysAndValues ...interface{})
	// Error logs an error message with optional key-value pairs.
	Error(msg string, keysAndValues ...interface{})
}

// EventHandler is a callback function for processing events.
// Return an error to stop event processing.
type EventHandler func(Event) error

// MetricsRegistry is an optional interface for collecting metrics.
// If provided, the library will report various operational metrics.
type MetricsRegistry interface {
	// Inc increments a counter metric by 1.
	Inc(name string)
	// Add adds a value to a counter metric.
	Add(name string, delta int64)
	// Set sets a gauge metric to a value.
	Set(name string, value int64)
}
