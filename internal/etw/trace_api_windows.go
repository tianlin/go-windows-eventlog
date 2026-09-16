//go:build windows && (amd64 || arm64)

package etw

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// traceAPI keeps lifecycle failure paths testable without elevated privileges.
type traceAPI interface {
	control(uint64, []uint16, uint32) (Stats, windows.Errno)
	close(uint64) windows.Errno
	process(uint64) windows.Errno
}

type windowsTraceAPI struct{}

func (windowsTraceAPI) control(h uint64, name []uint16, op uint32) (Stats, windows.Errno) {
	buf, p := properties(name)
	code, _, _ := controlTrace.Call(uintptr(h), 0, uintptr(unsafe.Pointer(p)), uintptr(op))
	runtime.KeepAlive(buf)
	return Stats{EventsLost: uint64(p.EventsLost), RealtimeBuffersLost: uint64(p.RealtimeBuffersLost)}, windows.Errno(code)
}
func (windowsTraceAPI) close(h uint64) windows.Errno {
	code, _, _ := closeTrace.Call(uintptr(h))
	return windows.Errno(code)
}
func (windowsTraceAPI) process(h uint64) windows.Errno {
	code, _, _ := processTrace.Call(uintptr(unsafe.Pointer(&h)), 1, 0, 0)
	return windows.Errno(code)
}
