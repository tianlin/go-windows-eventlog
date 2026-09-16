package eventlog

import (
	"errors"

	"github.com/tianlin/go-windows-eventlog/pkg/winevent"
)

// ErrETWUnsupported identifies configuration or recovery semantics unavailable
// from the real-time ETW backend.
var ErrETWUnsupported = errors.New("unsupported by real-time ETW")

// Capabilities describes source semantics independently of the reader API.
type Capabilities struct {
	Backend        string `json:"backend"`
	RealtimeOnly   bool   `json:"realtime_only"`
	NativeBookmark bool   `json:"native_bookmark"`
}

// CapabilityProvider is an optional EventLog extension describing source semantics.
type CapabilityProvider interface{ Capabilities() Capabilities }

// ETWData retains typed payloads and the original bytes owned by this library.
// Message templates are deliberately separate from a fully rendered message.
type ETWData struct {
	ChannelID       uint8          `json:"channel_id"`
	Level           uint8          `json:"level"`
	Task            uint16         `json:"task"`
	Opcode          uint8          `json:"opcode"`
	Keywords        uint64         `json:"keywords"`
	Properties      map[string]any `json:"properties,omitempty"`
	RawData         []byte         `json:"raw_data,omitempty"`
	MessageTemplate string         `json:"message_template,omitempty"`
	DecodeError     string         `json:"decode_error,omitempty"`
}

func (e *ETWData) fields() winevent.MapStr {
	m := winevent.MapStr{"channel_id": e.ChannelID, "level": e.Level, "task": e.Task, "opcode": e.Opcode, "keywords": e.Keywords}
	// TDH structures already are nested maps, and arrays contain typed values.
	// Avoid JSON conversion, which would turn large integers into float64.
	if len(e.Properties) != 0 {
		m["properties"] = e.Properties
	}
	if len(e.RawData) != 0 {
		m["raw_data"] = e.RawData
	}
	if e.MessageTemplate != "" {
		m["message_template"] = e.MessageTemplate
	}
	if e.DecodeError != "" {
		m["decode_error"] = e.DecodeError
	}
	return m
}

// ETWStats is cumulative for a reader, except QueueLength. Source counters are
// snapshots from ControlTrace; an unavailable query is reported explicitly.
// Received counts matching provider/channel events before record filters.
// QueueDropped counts full-queue drops; ResetDiscarded counts queued records
// discarded by Reset. Neither includes events lost upstream by Windows.
type ETWStats struct {
	Received            uint64 `json:"received"`
	QueueDropped        uint64 `json:"queue_dropped"`
	ResetDiscarded      uint64 `json:"reset_discarded"`
	DecodeFailures      uint64 `json:"decode_failures"`
	Reopens             uint64 `json:"reopens"`
	EventsLost          uint64 `json:"events_lost"`
	RealtimeBuffersLost uint64 `json:"realtime_buffers_lost"`
	BuffersRead         uint64 `json:"buffers_read"`
	QueueLength         int    `json:"queue_length"`
	StatisticsError     string `json:"statistics_error,omitempty"`
}

// ETWStatsProvider is an optional EventLog extension, implemented by ETW readers.
// ETWStats is safe to call concurrently with Read, Open, Reset and Close.
type ETWStatsProvider interface{ ETWStats() ETWStats }
