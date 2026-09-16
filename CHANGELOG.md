# Changelog

## Unreleased

- Add a real-time ETW backend for manifest Analytic/Debug channels through the
  existing EventLog interface on Windows amd64/arm64. Ordinary channels, XML
  queries and `.evtx` files retain their WinEvt behavior.
- Resolve owning/importing publishers and exact provider/channel ID mappings
  from Windows metadata. Reject incomplete mappings.
- Add optional `CapabilityProvider`, `ETWStatsProvider`, `Record.ETW`, and
  `Config.ETWQueueSize`. ETW reports its real-time-only/no-bookmark semantics;
  it does not fabricate source record IDs or recovery offsets.
- Preserve typed TDH properties, original payload and numeric event descriptors.
  Report partial decoding explicitly and bound decoding work and error output.
- Add bounded queue/drop statistics, concurrent close/reset handling, cleanup
  retries and cumulative loss-statistics warnings across reopened sessions.
- Recognize wrapped native errors in `IsRecoverable`.
- Add the ETW reader example, integration documentation, regression tests and
  Windows CI with native real-time integration tests and the race detector.

See [the ETW guide](docs/etw.md) for supported types, concurrency semantics and
limitations. This entry does not designate a published release.
