//go:build windows && (amd64 || arm64)

package etw

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The versioned namespace is reserved for this library. The executable path
// scopes recovery across service restarts; PID + creation time identifies the
// owner even after PID reuse. A counter distinguishes readers in one process.
// No disk registry or mutex is needed: we never reclaim a live owner's session,
// and session names cannot be reused by a later process incarnation.
var sessionNumber atomic.Uint64

func ownedSessionName() ([]uint16, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(exe))))
	prefix := fmt.Sprintf("go-windows-eventlog-v1-%x-", hash[:16])
	created, _, err := processIdentity(uint32(os.Getpid()))
	if err != nil {
		return nil, fmt.Errorf("identify ETW owner: %w", err)
	}
	if err := recoverOrphans(prefix, windowsOrphanAPI{}); err != nil {
		return nil, err
	}
	return windows.UTF16FromString(fmt.Sprintf("%s%d-%x-%d", prefix, os.Getpid(), created, sessionNumber.Add(1)))
}

type orphanAPI interface {
	list() ([]string, error)
	exited(uint32, uint64) (bool, error)
	stop(string) error
}

func recoverOrphans(prefix string, api orphanAPI) error {
	names, err := api.list()
	if err != nil {
		return err
	}
	for _, name := range names {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		pid, birth, ok := parseOwner(strings.TrimPrefix(name, prefix))
		if !ok {
			continue
		}
		dead, err := api.exited(pid, birth)
		if err != nil || !dead {
			continue
		}
		if err := api.stop(name); err != nil {
			return fmt.Errorf("reclaim orphan ETW session %s: %w", name, err)
		}
	}
	return nil
}

type windowsOrphanAPI struct{}

func processIdentity(pid uint32) (created uint64, exited bool, err error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return 0, false, err
	}
	defer windows.CloseHandle(h)
	var birth, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &birth, &exit, &kernel, &user); err != nil {
		return 0, false, err
	}
	// GetProcessTimes' exit time is undefined while the process is running.
	// A signaled process handle is the authoritative termination check.
	state, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return 0, false, err
	}
	return uint64(birth.HighDateTime)<<32 | uint64(birth.LowDateTime), state == windows.WAIT_OBJECT_0, nil
}

func (windowsOrphanAPI) exited(pid uint32, created uint64) (bool, error) {
	birth, exited, err := processIdentity(pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return true, nil
	} // PID no longer exists
	if err != nil {
		return false, err
	} // Never assume access denied means dead.
	return exited || birth != created, nil
}

func (windowsOrphanAPI) stop(name string) error {
	n, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	_, code := (windowsTraceAPI{}).control(0, n, 1)
	switch code {
	case 0, windows.ERROR_WMI_INSTANCE_NOT_FOUND, windows.ERROR_MORE_DATA:
		return nil // Another recovering process may already have stopped it.
	default:
		return code
	}
}

var queryAllTraces = advapi.NewProc("QueryAllTracesW")

func (windowsOrphanAPI) list() ([]string, error) {
	// ETW session and log file names each have space for 1024 UTF-16 chars.
	const chars = 1024
	header := int(unsafe.Sizeof(traceProperties{}))
	for count := 64; count <= 1024; count *= 2 {
		buffers := make([][]byte, count)
		pointers := make([]*traceProperties, count)
		for i := range buffers {
			buffers[i] = make([]byte, header+4*chars)
			p := (*traceProperties)(unsafe.Pointer(&buffers[i][0]))
			p.Size = uint32(len(buffers[i]))
			p.LoggerNameOffset = uint32(header)
			p.LogFileNameOffset = uint32(header + 2*chars)
			pointers[i] = p
		}
		var total uint32
		code, _, _ := queryAllTraces.Call(uintptr(unsafe.Pointer(&pointers[0])), uintptr(count), uintptr(unsafe.Pointer(&total)))
		runtime.KeepAlive(pointers)
		if windows.Errno(code) == windows.ERROR_MORE_DATA {
			continue
		}
		if code != 0 {
			return nil, fmt.Errorf("QueryAllTracesW: %w", windows.Errno(code))
		}
		if total > uint32(count) {
			return nil, fmt.Errorf("QueryAllTracesW returned invalid count %d", total)
		}
		names := make([]string, 0, total)
		for i := 0; i < int(total); i++ {
			b, off := buffers[i], int(pointers[i].LoggerNameOffset)
			if off < header || off%2 != 0 || off > len(b)-2 {
				return nil, fmt.Errorf("QueryAllTracesW returned invalid name offset")
			}
			names = append(names, windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&b[off])), (len(b)-off)/2)))
		}
		runtime.KeepAlive(buffers)
		return names, nil
	}
	return nil, fmt.Errorf("QueryAllTracesW session list kept growing")
}

// Keep parsing strict so legacy GUID-only names and unrelated session names
// cannot be mistaken for ownership records.
func parseOwner(name string) (uint32, uint64, bool) {
	parts := strings.Split(name, "-")
	if len(parts) != 3 {
		return 0, 0, false
	}
	pid, e1 := strconv.ParseUint(parts[0], 10, 32)
	birth, e2 := strconv.ParseUint(parts[1], 16, 64)
	number, e3 := strconv.ParseUint(parts[2], 10, 64)
	return uint32(pid), birth, e1 == nil && e2 == nil && e3 == nil && pid != 0 && birth != 0 && number != 0
}
