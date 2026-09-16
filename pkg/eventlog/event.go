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
	"strings"
	"time"

	"github.com/tianlin/go-windows-eventlog/pkg/checkpoint"
	"github.com/tianlin/go-windows-eventlog/pkg/winevent"
)

// Record represents a single event from the Windows Event Log.
type Record struct {
	winevent.Event
	ETW    *ETWData                 // Present only for real-time ETW events.
	File   string                   // Source file when event is from a file.
	XML    string                   // XML representation of the event.
	Offset checkpoint.EventLogState // Position of the record within its source stream.
}

// Event represents a processed event ready for consumption.
// This is the final output format that can be easily serialized or processed.
type Event struct {
	// Timestamp is the event creation time.
	Timestamp time.Time
	// Fields contains all event data in a structured format.
	Fields winevent.MapStr
	// Private contains internal state (like checkpoint information).
	Private interface{}
}

// ToMap converts the Record to a map structure suitable for serialization.
// This method transforms the raw Windows Event into a more user-friendly format,
// including ECS (Elastic Common Schema) compatible fields.
func (r Record) ToMap() winevent.MapStr {
	win := r.Fields()
	delete(win, "time_created")

	m := winevent.MapStr{
		"winlog": win,
	}
	if r.ETW != nil {
		delete(win, "record_id")
		m["etw"] = r.ETW
	}

	// ECS data
	setNestedField(m, "event.created", time.Now())

	if eventCode, ok := win["event_id"]; ok {
		setNestedField(m, "event.code", eventCode)
	}
	setNestedField(m, "event.kind", "event")
	setNestedField(m, "event.provider", r.Provider.Name)

	// Rename common fields to ECS format
	rename(m, "winlog.outcome", "event.outcome")
	rename(m, "winlog.level", "log.level")
	rename(m, "winlog.message", "message")
	rename(m, "winlog.error.code", "error.code")
	rename(m, "winlog.error.message", "error.message")

	// Add optional fields
	addOptional(m, "log.file.path", r.File)
	addOptional(m, "event.original", r.XML)
	addOptional(m, "event.action", r.Task)
	addOptional(m, "host.name", r.Computer)

	return m
}

// ToEvent converts the Record to an Event.
func (r Record) ToEvent() Event {
	return Event{
		Timestamp: r.TimeCreated.SystemTime,
		Fields:    r.ToMap(),
		Private:   r.Offset,
	}
}

// setNestedField sets a value in a nested map using dot notation.
// For example: setNestedField(m, "event.code", 123) sets m["event"]["code"] = 123
func setNestedField(m winevent.MapStr, key string, value interface{}) {
	keys := strings.Split(key, ".")
	current := m

	for i := 0; i < len(keys)-1; i++ {
		if _, exists := current[keys[i]]; !exists {
			current[keys[i]] = make(winevent.MapStr)
		}
		var ok bool
		current, ok = current[keys[i]].(winevent.MapStr)
		if !ok {
			// Try map[string]interface{} for backward compatibility
			if m, ok := current[keys[i]].(map[string]interface{}); ok {
				current = winevent.MapStr(m)
			} else {
				// Path exists but is not a map, cannot set nested field
				return
			}
		}
	}

	current[keys[len(keys)-1]] = value
}

// rename renames a map entry, overriding any previous value at the new key.
func rename(m winevent.MapStr, oldKey, newKey string) {
	v, err := getNestedField(m, oldKey)
	if err != nil {
		return
	}
	setNestedField(m, newKey, v)
	deleteNestedField(m, oldKey)
}

// addOptional adds a field to the map only if the value is not empty.
func addOptional(m winevent.MapStr, key string, value interface{}) {
	if value == nil {
		return
	}
	if s, ok := value.(string); ok && s == "" {
		return
	}
	setNestedField(m, key, value)
}

// getNestedField retrieves a value from a nested map using dot notation.
func getNestedField(m winevent.MapStr, key string) (interface{}, error) {
	keys := strings.Split(key, ".")
	current := m

	for i := 0; i < len(keys)-1; i++ {
		if _, exists := current[keys[i]]; !exists {
			return nil, nil
		}
		var ok bool
		current, ok = current[keys[i]].(winevent.MapStr)
		if !ok {
			// Try map[string]interface{} for backward compatibility
			if m, ok := current[keys[i]].(map[string]interface{}); ok {
				current = winevent.MapStr(m)
			} else {
				return nil, nil
			}
		}
	}

	return current[keys[len(keys)-1]], nil
}

// deleteNestedField deletes a value from a nested map using dot notation.
func deleteNestedField(m winevent.MapStr, key string) {
	keys := strings.Split(key, ".")
	current := m

	for i := 0; i < len(keys)-1; i++ {
		if _, exists := current[keys[i]]; !exists {
			return
		}
		var ok bool
		current, ok = current[keys[i]].(winevent.MapStr)
		if !ok {
			// Try map[string]interface{} for backward compatibility
			if m, ok := current[keys[i]].(map[string]interface{}); ok {
				current = winevent.MapStr(m)
			} else {
				return
			}
		}
	}

	delete(current, keys[len(keys)-1])
}
