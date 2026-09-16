//go:build windows && !amd64 && !arm64

package eventlog

import "fmt"

func newChannelETWReader(Config, []channelProvider) (EventLog, error) {
	return nil, fmt.Errorf("%w: ETW requires windows/amd64 or windows/arm64", ErrETWUnsupported)
}
