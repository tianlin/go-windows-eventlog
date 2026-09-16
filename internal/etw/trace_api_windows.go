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

type startupTraceAPI interface {
	traceAPI
	start([]uint16) (uint64, windows.Errno)
	open(*traceLogfile) (uint64, error)
	enable(uint64, Provider) windows.Errno
}

func (windowsTraceAPI) start(name []uint16) (uint64, windows.Errno) {
	var handle uint64
	buf, p := properties(name)
	code, _, _ := startTrace.Call(uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(p)))
	runtime.KeepAlive(buf)
	runtime.KeepAlive(name)
	return handle, windows.Errno(code)
}
func (windowsTraceAPI) open(logfile *traceLogfile) (uint64, error) {
	h, _, err := openTrace.Call(uintptr(unsafe.Pointer(logfile)))
	if h == ^uintptr(0) {
		return 0, err
	}
	return uint64(h), nil
}
func (windowsTraceAPI) enable(h uint64, p Provider) windows.Errno {
	code, _, _ := enableTrace.Call(uintptr(h), uintptr(unsafe.Pointer(&p.GUID)), 1, 0, 0, 0, 0, 0)
	return windows.Errno(code)
}

func (windowsTraceAPI) control(h uint64, name []uint16, op uint32) (Stats, windows.Errno) {
	buf, p := properties(name)
	var instanceName *uint16
	if len(name) != 0 {
		instanceName = &name[0]
	}
	code, _, _ := controlTrace.Call(uintptr(h), uintptr(unsafe.Pointer(instanceName)), uintptr(unsafe.Pointer(p)), uintptr(op))
	runtime.KeepAlive(buf)
	runtime.KeepAlive(name)
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
