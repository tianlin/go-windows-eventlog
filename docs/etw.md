# Real-time ETW backend

The ETW backend extends the existing `eventlog.EventLog` interface to manifest
Analytic/Debug channels. It requires Windows amd64 or arm64 and Go 1.23+.
The implementation uses Windows system DLLs through `x/sys/windows`; CGO and
additional module dependencies are not required.

## Source selection and compatibility

`eventlog.New(Config{Name: channelName})` reads the channel's Windows metadata.
Admin/Operational channels use WinEvt. Analytic/Debug channels use ETW after
resolving every owning/importing publisher to its GUID and ChannelReferenceID.
A missing mapping is an error; collecting a subset of publishers is not treated
as successful channel resolution. Event callbacks match both GUID and channel
ID before decoding or queueing events.

Existing `.evtx` reads retain their implementation. A nonempty XML `Query`
retains WinEvt query semantics: its Select paths, rather than the reader's Name,
identify the sources. This does not add XML query support for ETW; Windows'
existing limitations for querying/subscribing direct channels still apply.
Non-query `.etl` file reads are explicitly unsupported by this backend.

Automatic routing never relies on a channel name suffix or retries a failed
WinEvt subscription as ETW. For unavailable channel metadata before its type
can be established, existing deferred WinEvt error/IgnoreMissingChannel behavior
is preserved. Once a channel is identified as Analytic/Debug, mapping errors
are returned without falling back to WinEvt.

## Public API

```go
reader, err := eventlog.New(eventlog.Config{
    Name:         "Microsoft-Windows-WMI-Activity/Trace",
    BatchSize:    100,
    ETWQueueSize: 1024,
    // EventID, Level, Provider and IgnoreOlder retain record-filter semantics.
})
if err != nil { return err }
defer reader.Close()
if err := reader.Open(checkpoint.EventLogState{}); err != nil { return err }
records, err := reader.Read()
```

The original `EventLog` method set is unchanged. Optional interfaces expose:

| Interface | ETW behavior |
| --- | --- |
| `CapabilityProvider` | `Backend="etw"`, `RealtimeOnly=true`, `NativeBookmark=false` |
| `ETWStatsProvider` | Queue, decode, reset and Windows loss counters |
| `CheckpointProvider` | Not implemented: no native recovery position exists |

WinEvt implements `CapabilityProvider` with `Backend="winevt"` and
`NativeBookmark=true`. Existing consumers of its checkpoint API continue to work.

`ETWQueueSize` defaults to 1024 records. Allowed configuration values are 0
(default) through 1,048,576; memory depends on payload sizes and Go object
overhead, not only record count. `BatchSize` retains the existing default 100
and maximum 1024.

## Lifecycle and concurrency

- `Open` requires a completely zero `EventLogState`; even a state containing
  only a name is rejected. There is no historical replay before the session.
- `Read` waits for the first event, then returns currently available records up
  to BatchSize. Records already queued before a terminal error are returned
  first; a later Read returns that session's error or EOF.
- One goroutine should normally call Read. Close/Reset and statistics may run
  concurrently with it. Lifecycle changes are serialized. A Read already in
  progress retains its original session's terminal state after a reopen.
- `Close` stops only the library-owned session and closes its consumer. It
  waits for the consumer after successful cleanup, waking blocked reads. Queued
  records remain readable before EOF. A failed native cleanup retains ownership
  so Close can be retried; it does not promise the consumer has exited.
- `Reset` performs cleanup, discards the remaining old queue and counts those
  records as `ResetDiscarded`. A successful cleanup may still report the old
  consumer's terminal error; the reader can subsequently be opened with zero
  state. If cleanup itself fails, retry Reset/Close before opening.
- After a successful final Close the reader cannot reopen. Every successful
  Open after Reset creates a new session and increments `Reopens`.

Reopening does not recover events from the gap. No reconnect scheduling is
hidden inside the library. `IsRecoverable` recognizes wrapped native errors;
callers decide retry policy and must still use zero ETW recovery state.

## Event representation and decoding

The existing `winevent.Event` fields carry event ID, version, timestamp,
provider, channel, PID/TID, severity and correlation IDs. Actual ActivityID
comes from EVENT_HEADER and RelatedActivityID from extended event data.

`Record.ETW` and `ToEvent().Fields["etw"]` retain:

- numeric channel ID, level, task, opcode and full keyword mask;
- typed properties, including common scalar types, arrays and structures;
- a library-owned copy of the raw payload (base64 when encoded as JSON);
- the TDH message template and any decode error.

RecordID and Offset remain zero. `ToMap` omits `winlog.record_id` for ETW records.
Messages are not fabricated from templates: message insertion, enum/bitmap
name rendering and XML synthesis are not implemented. Use `MessageTemplate`
and typed `Properties` when a rendered message is unavailable.

Supported scalar inputs include UTF-16/ANSI strings, signed/unsigned integers,
finite floats, booleans, GUIDs, validated SIDs, pointers and binary values.
FILETIME remains its uint64 input value; SYSTEMTIME remains its original bytes.
Unsupported TDH/custom-schema inputs, non-finite JSON floats and malformed
payloads produce partial records with a DecodeError and the original payload.
They increment `DecodeFailures` rather than silently becoming successful empty
events. Dynamic counts must reference supported unsigned count fields;
unresolvable nested count references are reported as decode errors.

Each event is bounded to 4096 decoded values, 16 levels of property nesting and
1 MiB of decoded payload/metadata-string bytes. Metadata blocks are limited to
1 MiB. Names are cached within an event, error labels are truncated and at most
16 property errors are retained. Limits are not exact process-memory ceilings:
maps, slices, raw payload copies and allocator overhead require extra memory.
Events exceeding limits retain their raw payload and an explicit error.

## Backpressure and metrics

ETW enables all levels and keywords, then applies exact provider/channel and
record filtering. This includes verbose and custom levels when no Level filter
is given. It can be expensive for high-volume providers; provider-side keyword
or event-ID filter optimization and shared sessions are not implemented.

The native callback does not wait for the consumer when the Go queue is full;
it drops the new record. All payload decoding/copying finishes before the native
callback returns, so Record never retains Windows-owned payload pointers.

| Statistic | Meaning |
| --- | --- |
| `Received` | Matching provider/channel events before record filters |
| `QueueDropped` | New records dropped because the queue was full |
| `ResetDiscarded` | Queued records discarded during Reset |
| `DecodeFailures` | Matching events with incomplete/failed decoding |
| `Reopens` | Successful opens after the first |
| `EventsLost`, `RealtimeBuffersLost` | Session statistics reported by ControlTrace |
| `BuffersRead` | Buffers observed by the installed native buffer callback |
| `QueueLength` | Current queue occupancy |
| `StatisticsError` | Current query failure or incomplete historical statistics |

Counters are cumulative across sessions except QueueLength. If a final session
snapshot is unavailable/incomplete, its warning remains visible after successful
subsequent sessions; cumulative counts must not be interpreted as complete.

## Unsupported semantics

The ETW constructor rejects IncludeXML, CheckpointFile, explicit Forwarded,
non-default Locale, non-wait NoMoreEvents and nonzero recovery state with
`ErrETWUnsupported` (`errors.Is` is supported). XML Query configurations are
routed to WinEvt as described above. Windows/386 retains WinEvt support but
returns ErrETWUnsupported for resolved ETW channels.

Each reader owns one randomly named session. It does not install manifests,
change channel enable/retention policies or take over external sessions.
Operating-system session limits and provider authorization still apply.
Real-time privileges normally require an elevated shell or appropriate service/
Performance Log Users permissions.

## Validation and release scope

Tests cover real TDH decoding using a process-local fixture manifest, real WMI
channel metadata, exact filtering, lifecycle races/retries, partial decode
results, resource limits and serialization. The elevated integration test emits
numbered events to two fixture channels and verifies target events without
mixing, duplication or loss. See the [example guide](../examples/etw-reader/README.md).

The maintainer reported successful elevated WMI capture and native sequence
tests for the original PoC. The formal integration adds the fixes and regression
tests above. Local checks run under a non-elevated agent; updated elevated tests
and the race detector are also configured in the Windows CI workflow. No remote
CI result or production load guarantee is implied by adding that workflow.

Local verification of the integration passed on Windows amd64; the ETW,
decoder, lifecycle and example tests also ran successfully as native arm64
binaries on the current Windows ARM64 host. Windows/386 builds retain WinEvt
compatibility. The complete non-elevated suite passes when excluding the two
existing tests that install Windows event sources (`TestWindowsEventLogAPI`
and `TestEventIterator`); without those exclusions both report access denied.

This integration supports real-time manifest channels, not arbitrary ETW/MOF/
TraceLogging schemas, durable ETL recovery, automatic reconnect scheduling or
cross-reader session sharing. Those require separate extensions.

## Windows API references

- [Channel configuration properties](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_channel_config_property_id)
- [Publisher metadata](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_publisher_metadata_property_id)
- [ControlTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew)
- [CloseTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace)
- [TDH event information](https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_event_info)
