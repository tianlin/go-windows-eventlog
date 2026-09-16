# Windows Event Log fixtures

The `.evtx` files in this directory are test inputs and must be included in a
clean checkout. They are not generated logs from the development machine.

Source: [elastic/beats, winlogbeat/sys/wineventlog/testdata](https://github.com/elastic/beats/tree/fda1180ff39619f8cd80a43d6c6dda8d5b089169/winlogbeat/sys/wineventlog/testdata).
All 11 EVTX files were verified byte-for-byte using their Git blob hashes against
that revision. They accompany the existing tests and XML expectations derived
from Elasticsearch's Winlogbeat code, under the Apache License, Version 2.0.
