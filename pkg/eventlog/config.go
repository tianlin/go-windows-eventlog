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

package eventlog

import (
	"encoding/xml"
	"fmt"
	"time"
)

// Config is the configuration for reading Windows Event Logs.
type Config struct {
	// ETWQueueSize bounds the real-time ETW queue (default 1024).
	// Full queues drop new events and increment ETWStats.QueueDropped.
	ETWQueueSize int `yaml:"etw_queue_size,omitempty" json:"etw_queue_size,omitempty"`
	// Name is the name of the event log or the path to an .evtx file.
	// For channel-based reading: "Application", "Security", "System", etc.
	// For file-based reading: path to .evtx file
	Name string `yaml:"name" json:"name"`

	// ID is an optional identifier for the event log reader.
	// If not specified, Name is used as the ID.
	ID string `yaml:"id,omitempty" json:"id,omitempty"`

	// Query is an XPath query to filter events. If empty, all events are read.
	// Example: "*[System[(Level=1 or Level=2)]]" for errors and warnings only.
	// See: https://docs.microsoft.com/en-us/windows/win32/wes/consuming-events
	Query string `yaml:"query,omitempty" json:"query,omitempty"`

	// CheckpointFile is the path to the file where reading state is persisted.
	// This allows resuming from the last read position after a restart.
	CheckpointFile string `yaml:"checkpoint_file,omitempty" json:"checkpoint_file,omitempty"`

	// BatchSize is the maximum number of events to read in a single batch.
	// Default: 100, maximum: 1024
	BatchSize int `yaml:"batch_size,omitempty" json:"batch_size,omitempty"`

	// IgnoreOlder ignores events older than this duration.
	// Default: 0 (read all events)
	IgnoreOlder time.Duration `yaml:"ignore_older,omitempty" json:"ignore_older,omitempty"`

	// Level filters events by severity level (e.g., "critical", "error", "warning", "information", "verbose").
	Level string `yaml:"level,omitempty" json:"level,omitempty"`

	// EventID filters events by event ID. Format: "1,2,3-10,-100" (whitelist/blacklist).
	EventID string `yaml:"event_id,omitempty" json:"event_id,omitempty"`

	// Provider filters events by provider name (source).
	Provider []string `yaml:"provider,omitempty" json:"provider,omitempty"`

	// IncludeXML includes the raw XML representation of events in the output.
	// This can be useful for debugging but increases memory usage.
	// Default: false
	IncludeXML bool `yaml:"include_xml,omitempty" json:"include_xml,omitempty"`

	// Forwarded indicates whether to treat this as a forwarded events channel.
	// Forwarded events are rendered differently to avoid local metadata lookups.
	// If not specified, defaults to true for the "ForwardedEvents" channel.
	Forwarded *bool `yaml:"forwarded,omitempty" json:"forwarded,omitempty"`

	// Locale is the locale ID for rendering messages.
	// Default: 0 (system default locale)
	Locale uint32 `yaml:"locale,omitempty" json:"locale,omitempty"`

	// IgnoreMissingChannel controls whether to ignore errors when the channel doesn't exist.
	// Useful for reading from channels that may not be present on all systems.
	// Default: true for channels, false for files
	IgnoreMissingChannel *bool `yaml:"ignore_missing_channel,omitempty" json:"ignore_missing_channel,omitempty"`

	// NoMoreEvents defines what action to take when no more events are available.
	// Options: "wait" (default) or "stop".
	NoMoreEvents string `yaml:"no_more_events,omitempty" json:"no_more_events,omitempty"`
}

type query struct {
	IgnoreOlder time.Duration
	EventID     string
	Level       string
	Provider    []string
}

func (c Config) recordQuery() query {
	return query{
		IgnoreOlder: c.IgnoreOlder,
		EventID:     c.EventID,
		Level:       c.Level,
		Provider:    c.Provider,
	}
}

// Validate validates the configuration and sets defaults.
func (c *Config) Validate() error {
	if c.ETWQueueSize < 0 || c.ETWQueueSize > 1048576 {
		return fmt.Errorf("etw_queue_size must be between 0 and 1048576")
	}
	if c.Name == "" {
		return fmt.Errorf("event log name cannot be empty")
	}

	// Set defaults
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	}

	if c.BatchSize > 1024 {
		return fmt.Errorf("batch_size cannot exceed 1024, got %d", c.BatchSize)
	}

	// Validate XML query syntax if provided
	if c.Query != "" {
		if err := xml.Unmarshal([]byte(c.Query), &struct{}{}); err != nil {
			return fmt.Errorf("invalid xml query: %w", err)
		}
	}

	return nil
}

// RunConfig contains runtime configuration for the event log runner.
type RunConfig struct {
	// MetricsRegistry is an optional metrics collector.
	MetricsRegistry MetricsRegistry

	// StatusReporter is an optional status reporter.
	StatusReporter StatusReporter

	// Logger is the logger to use. If nil, logging is disabled.
	Logger Logger
}

// RunOption is a functional option for configuring the event log runner.
type RunOption func(*RunConfig)

// WithMetrics sets the metrics registry.
func WithMetrics(registry MetricsRegistry) RunOption {
	return func(c *RunConfig) {
		c.MetricsRegistry = registry
	}
}

// WithStatusReporter sets the status reporter.
func WithStatusReporter(reporter StatusReporter) RunOption {
	return func(c *RunConfig) {
		c.StatusReporter = reporter
	}
}

// WithLogger sets the logger.
func WithLogger(logger Logger) RunOption {
	return func(c *RunConfig) {
		c.Logger = logger
	}
}
