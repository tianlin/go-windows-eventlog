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

//go:build windows

package eventlog

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/tianlin/go-windows-eventlog/pkg/checkpoint"
	"github.com/tianlin/go-windows-eventlog/pkg/wineventlog"
)

var errRecordIDGap = errors.New("record ID gap detected")
var errRenderNoEvent = errors.New("rendering error without partial event")

const renderNoEventRetryLimit = 3
const recordIDGapRetryLimit = 3

type gapDetectedError struct {
	channel  string
	previous uint64
	current  uint64
	bookmark string
}

func (e *gapDetectedError) Error() string {
	return fmt.Sprintf("%v in channel %q (previous=%d current=%d)",
		errRecordIDGap, e.channel, e.previous, e.current)
}

func (e *gapDetectedError) Unwrap() error { return errRecordIDGap }

func (e *gapDetectedError) Bookmark() string { return e.bookmark }

func (e *gapDetectedError) RetryKey() string {
	return fmt.Sprintf("%s:%d:%d", e.channel, e.previous, e.current)
}

type renderNoEventError struct {
	cause    error
	bookmark string
}

func (e *renderNoEventError) Error() string {
	if e.cause == nil {
		return errRenderNoEvent.Error()
	}
	return fmt.Sprintf("%v: %v", errRenderNoEvent, e.cause)
}

func (e *renderNoEventError) Unwrap() error { return errRenderNoEvent }

func (e *renderNoEventError) Bookmark() string { return e.bookmark }

func (e *renderNoEventError) RetryKey() string {
	if e.bookmark != "" {
		return e.bookmark
	}
	return fmt.Sprintf("no-bookmark:%v", e.cause)
}

func (l *winEventLog) newRenderNoEventError(handle wineventlog.EvtHandle, cause error) *renderNoEventError {
	bookmark, bookmarkErr := l.createBookmarkFromEvent(handle)
	return &renderNoEventError{
		cause:    errors.Join(cause, bookmarkErr),
		bookmark: bookmark,
	}
}

// winEventLog implements the EventLog interface for reading from the Windows
// Event Log API.
type winEventLog struct {
	config      Config
	query       string
	filter      *recordFilter
	id          string // Identifier of this event log.
	channelName string // Name of the channel from which to read.
	file        bool   // Reading from file rather than channel.
	maxRead     int    // Maximum number returned in one Read.
	lastRead    checkpoint.EventLogState
	log         Logger

	iterator *wineventlog.EventIterator
	renderer wineventlog.EventRenderer

	renderNoEventKey   string
	renderNoEventCount int
	gapRetryKey        string
	gapRetryCount      int
}

var _ CheckpointProvider = (*winEventLog)(nil)

// New creates and returns a new EventLog instance based on the given config.
func New(config Config) (EventLog, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if reader, handled, err := routeETW(config); handled {
		return reader, err
	}

	id := config.ID
	if id == "" {
		id = config.Name
	}

	l := &winEventLog{
		config:      config,
		id:          id,
		channelName: config.Name,
		maxRead:     config.BatchSize,
		log:         &noopLogger{},
	}

	var err error
	if config.Query != "" {
		l.query = config.Query
	} else {
		if info, err := os.Stat(config.Name); err == nil && info.Mode().IsRegular() {
			path, err := filepath.Abs(config.Name)
			if err != nil {
				return nil, err
			}
			l.file = true
			l.channelName = path
		}

		l.filter, err = newRecordFilter(config.recordQuery())
		if err != nil {
			return nil, err
		}
		l.query = "*"
	}

	// Create the renderer
	if config.IncludeXML || l.isForwarded() {
		l.renderer = wineventlog.NewXMLRenderer(
			config.Locale,
			l.isForwarded(),
			wineventlog.NilHandle)
	} else {
		l.renderer, err = wineventlog.NewRenderer(
			config.Locale,
			wineventlog.NilHandle)
		if err != nil {
			return nil, err
		}
	}

	return l, nil
}

func (l *winEventLog) Capabilities() Capabilities {
	return Capabilities{Backend: "winevt", NativeBookmark: true}
}

func (l *winEventLog) isForwarded() bool {
	c := l.config
	return (c.Forwarded != nil && *c.Forwarded) || (c.Forwarded == nil && c.Name == "ForwardedEvents")
}

// Name returns the name of the event log (i.e. Application, Security, etc.).
func (l *winEventLog) Name() string {
	return l.id
}

// Channel returns the event log's channel name.
func (l *winEventLog) Channel() string {
	return l.channelName
}

// IsFile returns true if the event log is an evtx file.
func (l *winEventLog) IsFile() bool {
	return l.file
}

// Checkpoint returns the latest source position reached by the reader.
func (l *winEventLog) Checkpoint() checkpoint.EventLogState {
	return l.lastRead
}

func (l *winEventLog) Open(state checkpoint.EventLogState) error {
	l.lastRead = state

	var err error
	l.iterator, err = wineventlog.NewEventIterator(
		wineventlog.WithSubscriptionFactory(func() (handle wineventlog.EvtHandle, err error) {
			return l.open(l.lastRead)
		}),
		wineventlog.WithBatchSize(l.maxRead))
	return err
}

func (l *winEventLog) open(state checkpoint.EventLogState) (wineventlog.EvtHandle, error) {
	var bookmark wineventlog.Bookmark
	if len(state.Bookmark) > 0 {
		var err error
		bookmark, err = wineventlog.NewBookmarkFromXML(state.Bookmark)
		if err != nil {
			return wineventlog.NilHandle, err
		}
		defer bookmark.Close()
	}

	if l.file {
		return l.openFile(state, bookmark)
	}
	return l.openChannel(bookmark)
}

func (l *winEventLog) openFile(state checkpoint.EventLogState, bookmark wineventlog.Bookmark) (wineventlog.EvtHandle, error) {
	path := l.channelName

	h, err := wineventlog.EvtQuery(0, path, l.query, wineventlog.EvtQueryFilePath|wineventlog.EvtQueryForwardDirection)
	if err != nil {
		return wineventlog.NilHandle, fmt.Errorf("failed to get handle to event log file %v: %w", path, err)
	}

	if bookmark > 0 {
		if l.log != nil {
			l.log.Debug("Seeking to bookmark", "timestamp", state.Timestamp, "bookmark", state.Bookmark)
		}

		// This seeks to the last read event and strictly validates that the
		// bookmarked record number exists.
		if err = wineventlog.EvtSeek(h, 0, wineventlog.EvtHandle(bookmark), wineventlog.EvtSeekRelativeToBookmark|wineventlog.EvtSeekStrict); err == nil {
			// Then we advance past the last read event to avoid sending that
			// event again. This won't fail if we're at the end of the file.
			if seekErr := wineventlog.EvtSeek(h, 1, wineventlog.EvtHandle(bookmark), wineventlog.EvtSeekRelativeToBookmark); seekErr != nil {
				err = fmt.Errorf("failed to seek past bookmarked position: %w", seekErr)
			}
		} else {
			if l.log != nil {
				l.log.Warn("Failed to seek to bookmarked location, recovering by reading from beginning",
					"path", path, "error", err)
			}
			if seekErr := wineventlog.EvtSeek(h, 0, 0, wineventlog.EvtSeekRelativeToFirst); seekErr != nil {
				err = fmt.Errorf("failed to seek to beginning of log: %w", seekErr)
			}
		}

		if err != nil {
			return wineventlog.NilHandle, err
		}
	}

	return h, err
}

func (l *winEventLog) openChannel(bookmark wineventlog.Bookmark) (wineventlog.EvtHandle, error) {
	// Using a pull subscription to receive events. See:
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa385771(v=vs.85).aspx#pull
	signalEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return wineventlog.NilHandle, err
	}
	defer windows.CloseHandle(signalEvent) //nolint:errcheck // This is just a resource release.

	var flags wineventlog.EvtSubscribeFlag
	if bookmark > 0 {
		flags = wineventlog.EvtSubscribeStartAfterBookmark
		if !l.isForwarded() {
			// Use EvtSubscribeStrict to detect when the bookmark is missing and be able to
			// subscribe again from the beginning.
			flags |= wineventlog.EvtSubscribeStrict
		}
	} else {
		flags = wineventlog.EvtSubscribeStartAtOldestRecord
	}

	if l.log != nil {
		l.log.Debug("Using subscription query", "query", l.query)
	}
	channelPath := ""
	if l.config.Query == "" {
		channelPath = l.channelName
	}

	h, err := wineventlog.Subscribe(
		0, // Session - nil for localhost
		signalEvent,
		channelPath,
		l.query,                         // Query - nil means all events
		wineventlog.EvtHandle(bookmark), // Bookmark - for resuming from a specific event
		flags)

	if err == nil {
		return h, nil
	}
	if errors.Is(err, wineventlog.ERROR_NOT_FOUND) ||
		errors.Is(err, wineventlog.ERROR_EVT_QUERY_RESULT_STALE) ||
		errors.Is(err, wineventlog.ERROR_EVT_QUERY_RESULT_INVALID_POSITION) {
		// The bookmarked event was not found, we retry the subscription from the start.
		l.resetLastRead()
		return wineventlog.Subscribe(0, signalEvent, channelPath, l.query, 0, wineventlog.EvtSubscribeStartAtOldestRecord)
	}
	return 0, err
}

func (l *winEventLog) Read() ([]Record, error) {
	var records []Record

	for h, ok := l.iterator.Next(); ok; h, ok = l.iterator.Next() {
		record, err := l.processHandle(h)
		if err != nil {
			if returnErr := l.handleProcessError(err); returnErr != nil {
				return records, returnErr
			}
			continue
		}
		l.resetRenderNoEventRetry()
		l.resetGapRetry()
		if l.filter != nil && !l.filter.match(record) {
			continue
		}
		records = append(records, *record)

		// It has read the maximum requested number of events.
		if len(records) >= l.maxRead {
			return records, nil
		}
	}

	// An error occurred while retrieving more events.
	if err := l.iterator.Err(); err != nil {
		return records, err
	}

	// Reader is configured to stop when there are no more events.
	if l.config.NoMoreEvents == "stop" {
		return records, io.EOF
	}

	return records, nil
}

func (l *winEventLog) handleProcessError(err error) error {
	var renderErr *renderNoEventError
	if errors.As(err, &renderErr) {
		l.resetGapRetry()
		retryCount := l.incrementRenderNoEventRetry(renderErr.RetryKey())
		if retryCount <= renderNoEventRetryLimit {
			return err
		}

		if l.log != nil {
			l.log.Error("Dropping poison event after repeated render failures",
				"channel", l.channelName,
				"retry_count", retryCount,
				"retry_limit", renderNoEventRetryLimit)
		}
		if bookmark := renderErr.Bookmark(); bookmark != "" {
			l.lastRead.Bookmark = bookmark
		} else {
			if l.log != nil {
				l.log.Error("Dropping poison event without bookmark after repeated render failures",
					"channel", l.channelName,
					"retry_count", retryCount,
					"retry_limit", renderNoEventRetryLimit)
			}
			l.resetRenderNoEventRetry()
			return nil
		}
		l.lastRead.RecordNumber = 0
		l.resetRenderNoEventRetry()
		return nil
	}

	l.resetRenderNoEventRetry()
	var gapErr *gapDetectedError
	if errors.As(err, &gapErr) {
		retryCount := l.incrementGapRetry(gapErr.RetryKey())
		if retryCount <= recordIDGapRetryLimit {
			return err
		}

		if l.log != nil {
			l.log.Error("Accepting record ID gap after repeated retries",
				"channel", l.channelName,
				"retry_count", retryCount,
				"retry_limit", recordIDGapRetryLimit,
				"previous_record_id", gapErr.previous,
				"current_record_id", gapErr.current,
				"missing", gapErr.current-gapErr.previous-1)
		}
		if bookmark := gapErr.Bookmark(); bookmark != "" {
			l.lastRead.Bookmark = bookmark
		}
		l.lastRead.RecordNumber = gapErr.current
		l.resetGapRetry()
		return nil
	}

	l.resetGapRetry()
	if errors.Is(err, errRecordIDGap) || errors.Is(err, errRenderNoEvent) {
		return err
	}
	if l.log != nil {
		l.log.Warn("Dropping event due to rendering error", "error", err)
	}
	return nil
}

func (l *winEventLog) processHandle(h wineventlog.EvtHandle) (*Record, error) {
	defer h.Close()

	// NOTE: Render can return an error and a partial event.
	evt, xml, err := l.renderer.Render(h)
	if evt == nil {
		return nil, l.newRenderNoEventError(h, err)
	}
	if err != nil {
		evt.RenderErr = append(evt.RenderErr, err.Error())
	}

	r := &Record{
		Event: *evt,
	}

	if l.config.IncludeXML {
		r.XML = xml
	}

	if l.file {
		r.File = l.id
	}

	previousRecordID := l.lastRead.RecordNumber
	if l.shouldCheckRecordIDGap() && previousRecordID > 0 && r.RecordID > previousRecordID+1 {
		if l.log != nil {
			l.log.Warn("Record ID gap detected, resetting subscription",
				"channel", l.channelName,
				"previous_record_id", previousRecordID,
				"current_record_id", r.RecordID,
				"missing", r.RecordID-previousRecordID-1)
		}
		return nil, l.newGapDetectedError(h, previousRecordID, r.RecordID)
	}

	r.Offset = checkpoint.EventLogState{
		Name:         l.id,
		RecordNumber: r.RecordID,
		Timestamp:    r.TimeCreated.SystemTime,
	}

	if r.Offset.Bookmark, err = l.createBookmarkFromEvent(h); err != nil {
		if l.log != nil {
			l.log.Warn("Failed creating bookmark", "error", err)
		}
	}
	l.lastRead = r.Offset
	return r, nil
}

func (l *winEventLog) shouldCheckRecordIDGap() bool {
	return l.config.Query == "" && !l.file && !l.isForwarded()
}

func (l *winEventLog) newGapDetectedError(handle wineventlog.EvtHandle, previousRecordID, currentRecordID uint64) *gapDetectedError {
	bookmark, err := l.createBookmarkFromEvent(handle)
	if err != nil && l.log != nil {
		l.log.Warn("Failed creating bookmark for record ID gap recovery", "error", err)
	}
	return &gapDetectedError{
		channel:  l.channelName,
		previous: previousRecordID,
		current:  currentRecordID,
		bookmark: bookmark,
	}
}

func (l *winEventLog) createBookmarkFromEvent(evtHandle wineventlog.EvtHandle) (string, error) {
	bookmark, err := wineventlog.NewBookmarkFromEvent(evtHandle)
	if err != nil {
		return "", fmt.Errorf("failed to create new bookmark from event handle: %w", err)
	}
	defer bookmark.Close()

	return bookmark.XML()
}

func (l *winEventLog) Reset() error {
	if l.log != nil {
		l.log.Debug("Closing event log reader handles for reset")
	}
	// Only close the iterator, keep the renderer alive to avoid
	// unnecessarily recreating render contexts. The renderer's
	// systemContext and userContext should remain valid across
	// session resets since they were created independently.
	if l.iterator == nil {
		return nil
	}
	err := l.iterator.Close()
	l.iterator = nil
	return err
}

func (l *winEventLog) Close() error {
	if l.log != nil {
		l.log.Debug("Closing event log reader handles")
	}
	return l.close()
}

func (l *winEventLog) close() error {
	if l.iterator == nil {
		return l.renderer.Close()
	}
	return errors.Join(
		l.iterator.Close(),
		l.renderer.Close(),
	)
}

func (l *winEventLog) incrementRenderNoEventRetry(key string) int {
	if key == l.renderNoEventKey && l.renderNoEventCount > 0 {
		l.renderNoEventCount++
		return l.renderNoEventCount
	}
	l.renderNoEventKey = key
	l.renderNoEventCount = 1
	return l.renderNoEventCount
}

func (l *winEventLog) resetRenderNoEventRetry() {
	l.renderNoEventKey = ""
	l.renderNoEventCount = 0
}

func (l *winEventLog) incrementGapRetry(key string) int {
	if key == l.gapRetryKey && l.gapRetryCount > 0 {
		l.gapRetryCount++
		return l.gapRetryCount
	}
	l.gapRetryKey = key
	l.gapRetryCount = 1
	return l.gapRetryCount
}

func (l *winEventLog) resetGapRetry() {
	l.gapRetryKey = ""
	l.gapRetryCount = 0
}

func (l *winEventLog) resetLastRead() {
	l.lastRead.Bookmark = ""
	l.lastRead.RecordNumber = 0
}

// SetLogger sets the logger for this event log reader.
func (l *winEventLog) SetLogger(logger Logger) {
	if logger != nil {
		l.log = logger
	}
}
