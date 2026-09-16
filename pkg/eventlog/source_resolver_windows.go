//go:build windows

package eventlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// XML Query is authoritative and remains on WinEvt. Name may be only a reader
// label in that case; automatic ETW routing is for channel-name configuration.
func routeETW(c Config) (EventLog, bool, error) {
	if c.Query != "" {
		return nil, false, nil
	}
	if strings.EqualFold(filepath.Ext(c.Name), ".etl") {
		return nil, true, fmt.Errorf("%w: ETL file reading", ErrETWUnsupported)
	}
	if strings.EqualFold(filepath.Ext(c.Name), ".evtx") {
		return nil, false, nil
	}
	if info, err := os.Stat(c.Name); err == nil && info.Mode().IsRegular() {
		return nil, false, nil
	}
	typ, p, err := resolveETWChannel(c.Name)
	if err != nil {
		// Preserve WinEvt's deferred error/IgnoreMissingChannel behavior when the
		// channel type is not known. Never retry a failed subscription using ETW.
		if typ != 2 && typ != 3 {
			return nil, false, nil
		}
		return nil, true, err
	}
	if typ != 2 && typ != 3 {
		return nil, false, nil
	}
	l, err := newChannelETWReader(c, p)
	return l, true, err
}
