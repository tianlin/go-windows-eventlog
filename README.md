# go-windows-eventlog

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Go library for reading Windows Event Logs, based on [Elastic Beats](https://github.com/elastic/beats) v9.2.1 with relevant Winlog fixes ported from v9.2.7.

## Installation

```bash
go get github.com/tianlin/go-windows-eventlog
```

**Requirements:** Go 1.23+, Windows OS

## Real-time ETW channels

Analytic/Debug channels with manifest metadata can now use the same
`eventlog.New → Open → Read → Close` interface through the ETW backend on
Windows amd64/arm64. The backend is selected from Windows channel metadata;
ordinary channels, XML queries and `.evtx` files retain the WinEvt backend.

See [the ETW integration guide](docs/etw.md) for API semantics and supported
payload types, and [the ETW reader example](examples/etw-reader/README.md) for
commands. ETW is real-time only: it does not provide native bookmarks, historical
replay or recovery of events missed while stopped. Use the optional
`CapabilityProvider` interface instead of assuming every reader supports
`CheckpointProvider`.

## Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/tianlin/go-windows-eventlog/pkg/eventlog"
)

func main() {
    cfg := eventlog.Config{
        Name:           "Application",
        CheckpointFile: ".checkpoint.yml",
        BatchSize:      100,
    }

    if err := cfg.Validate(); err != nil {
        log.Fatal(err)
    }

    reader, err := eventlog.NewReader(cfg, eventlog.NewStdLogger(nil))
    if err != nil {
        log.Fatal(err)
    }
    defer reader.Close()

    ctx := context.Background()
    err = reader.Read(ctx, func(event eventlog.Event) error {
        fmt.Printf("Event ID: %v, Provider: %s\n",
            event.Fields["event.code"],
            event.Fields["event.provider"])
        return nil
    })

    if err != nil {
        log.Fatal(err)
    }
}
```

## Source

Originally extracted from the [elastic/beats](https://github.com/elastic/beats) v9.2.1 Winlogbeat module. Version 0.1.2 incrementally ports the relevant Winlog changes from Beats v9.2.1 through v9.2.7 while preserving the v0.1.1 public API.

## License

Apache License 2.0 - Same as the original Elastic Beats project.
