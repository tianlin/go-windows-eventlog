//go:build windows && (amd64 || arm64)

package etw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/tianlin/go-windows-eventlog/pkg/sys"
	"golang.org/x/sys/windows"
)

var tdh = windows.NewLazySystemDLL("tdh.dll")
var getInfo = tdh.NewProc("TdhGetEventInformation")
var getPropertySize = tdh.NewProc("TdhGetPropertySize")
var getProperty = tdh.NewProc("TdhGetProperty")

type propertyDescriptor struct {
	Name            uint64
	Index, Reserved uint32
}
type propertyInfo struct {
	Flags, Name   uint32
	Type, OutType uint16
	Map           uint32
	Count, Length uint16
	Tags          uint32
}

const maxDecodedValues = 4096
const maxDecodedBytes = 1 << 20

var errDecodeLimit = errors.New("ETW decoding resource limit")

// Limits apply to the whole event, including nested structures/arrays. Per-
// property limits alone allow multiplicative allocation on nested templates.
type decodeBudget struct{ values, bytes int }

func (b *decodeBudget) takeValues(n int) error {
	if n < 0 || n > b.values {
		return fmt.Errorf("%w: decoded values", errDecodeLimit)
	}
	b.values -= n
	return nil
}
func (b *decodeBudget) takeBytes(n int) error {
	if n < 0 || n > b.bytes {
		return fmt.Errorf("%w: decoded bytes", errDecodeLimit)
	}
	b.bytes -= n
	return nil
}

func utf16String(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("odd UTF-16 length")
	}
	u := make([]uint16, 0, min(len(b)/2, 128))
	for i := 0; i < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i:])
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return string(utf16.Decode(u)), nil
}

func metadataString(b []byte, offset uint32) string {
	if offset == 0 || offset >= uint32(len(b)) || offset%2 != 0 {
		return ""
	}
	s, _ := utf16String(b[offset:])
	return s
}

func propertyBytes(r *eventRecord, path []propertyDescriptor, budget *decodeBudget) ([]byte, error) {
	var size uint32
	status, _, _ := getPropertySize.Call(uintptr(unsafe.Pointer(r)), 0, 0, uintptr(len(path)), uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(&size)))
	if status != 0 {
		return nil, fmt.Errorf("TdhGetPropertySize: %w", windows.Errno(status))
	}
	if size > 1<<20 {
		return nil, fmt.Errorf("property too large: %d", size)
	}
	if err := budget.takeBytes(int(size)); err != nil {
		return nil, err
	}
	if size == 0 {
		return []byte{}, nil
	}
	b := make([]byte, size)
	status, _, _ = getProperty.Call(uintptr(unsafe.Pointer(r)), 0, 0, uintptr(len(path)), uintptr(unsafe.Pointer(&path[0])), uintptr(size), uintptr(unsafe.Pointer(&b[0])))
	runtime.KeepAlive(path)
	if status != 0 {
		return nil, fmt.Errorf("TdhGetProperty: %w", windows.Errno(status))
	}
	return b, nil
}

func decodeEvent(r *eventRecord, e *Event) error {
	// EventWriteString events do not have manifest property metadata.
	if r.Header.Flags&4 != 0 {
		s, err := utf16String(e.RawData)
		e.Properties = map[string]any{"message": s}
		return err
	}
	var size uint32
	status, _, _ := getInfo.Call(uintptr(unsafe.Pointer(r)), 0, 0, 0, uintptr(unsafe.Pointer(&size)))
	if status != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return fmt.Errorf("TdhGetEventInformation: %w", windows.Errno(status))
	}
	if size < 112 || size > 1<<20 {
		return fmt.Errorf("invalid TDH metadata size: %d", size)
	}
	b := make([]byte, size)
	status, _, _ = getInfo.Call(uintptr(unsafe.Pointer(r)), 0, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)))
	if status != 0 {
		return fmt.Errorf("TdhGetEventInformation: %w", windows.Errno(status))
	}
	return decodeMetadata(r, e, b)
}

func decodeMetadata(r *eventRecord, e *Event, b []byte) error {
	if len(b) < 112 {
		return fmt.Errorf("truncated TDH metadata")
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
	count, top := u32(100), u32(104)
	if top > count || count > maxDecodedValues || uint64(count)*24+112 > uint64(len(b)) {
		return fmt.Errorf("invalid TDH property table")
	}
	budget := &decodeBudget{values: maxDecodedValues, bytes: maxDecodedBytes}
	stringsByOffset := map[uint32]string{}
	getString := func(offset uint32) (string, error) {
		if s, ok := stringsByOffset[offset]; ok {
			return s, nil
		}
		s := metadataString(b, offset)
		if err := budget.takeBytes(len(s)); err != nil {
			return "", err
		}
		stringsByOffset[offset] = s
		return s, nil
	}
	var err error
	if e.TaskName, err = getString(u32(72)); err != nil {
		return err
	}
	if e.OpcodeName, err = getString(u32(76)); err != nil {
		return err
	}
	if e.MessageTemplate, err = getString(u32(80)); err != nil {
		return err
	}
	var props []propertyInfo
	if count > 0 {
		props = unsafe.Slice((*propertyInfo)(unsafe.Pointer(&b[112])), int(count))
	}
	e.Properties = make(map[string]any)
	var read func(int, []propertyDescriptor, int) (any, error)
	read = func(index int, parent []propertyDescriptor, depth int) (any, error) {
		if depth > 16 || index < 0 || index >= len(props) {
			return nil, fmt.Errorf("invalid property nesting/index")
		}
		p := props[index]
		name, err := getString(p.Name)
		if err != nil {
			return nil, err
		}
		if name == "" {
			return nil, fmt.Errorf("invalid property name")
		}
		if p.Flags&0x80 != 0 {
			return nil, fmt.Errorf("custom TDH schema not supported")
		}
		n := int(p.Count)
		if p.Flags&4 != 0 {
			// A count property references another property in the same event. Keep
			// scalar count reads separate to avoid recursive cycles in bad metadata.
			if int(p.Count) >= len(props) {
				return nil, fmt.Errorf("invalid count reference")
			}
			cp := props[p.Count]
			name, err := getString(cp.Name)
			if err != nil {
				return nil, err
			}
			if name == "" {
				return nil, fmt.Errorf("invalid count name")
			}
			path := []propertyDescriptor{{Name: uint64(uintptr(unsafe.Pointer(&b[cp.Name]))), Index: 0xffffffff}}
			raw, err := propertyBytes(r, path, budget)
			if err != nil {
				return nil, err
			}
			v, err := decodeValue(cp.Type, raw)
			if err != nil {
				return nil, err
			}
			switch x := v.(type) {
			case uint8:
				n = int(x)
			case uint16:
				n = int(x)
			case uint32:
				if x > 4096 {
					return nil, fmt.Errorf("array too large")
				}
				n = int(x)
			default:
				return nil, fmt.Errorf("unsupported count type %T", v)
			}
		}
		if n > 4096 {
			return nil, fmt.Errorf("array too large: %d", n)
		}
		if err := budget.takeValues(max(n, 1)); err != nil {
			return nil, err
		}
		values := make([]any, 0, n)
		for i := 0; i < n; i++ {
			path := append(append([]propertyDescriptor(nil), parent...), propertyDescriptor{Name: uint64(uintptr(unsafe.Pointer(&b[p.Name]))), Index: uint32(i)})
			if p.Flags&1 != 0 {
				m := map[string]any{}
				for j := 0; j < int(p.OutType); j++ {
					idx := int(p.Type) + j
					if idx >= len(props) {
						return nil, fmt.Errorf("invalid struct member")
					}
					v, err := read(idx, path, depth+1)
					if err != nil {
						return nil, err
					}
					name, err := getString(props[idx].Name)
					if err != nil {
						return nil, err
					}
					m[name] = v
				}
				values = append(values, m)
			} else {
				raw, err := propertyBytes(r, path, budget)
				if err != nil {
					return nil, err
				}
				v, err := decodeValue(p.Type, raw)
				if err != nil {
					return nil, err
				}
				values = append(values, v)
			}
		}
		if n == 1 && p.Flags&(4|32) == 0 {
			return values[0], nil
		}
		return values, nil
	}
	var errs []error
	for i := 0; i < int(top); i++ {
		name, err := getString(props[i].Name)
		if err != nil {
			return errors.Join(append(errs, err)...)
		}
		v, err := read(i, nil, 0)
		if err != nil {
			errs = append(errs, fmt.Errorf("property %.128q: %w", name, err))
			if errors.Is(err, errDecodeLimit) || len(errs) >= 16 {
				errs = append(errs, fmt.Errorf("remaining properties omitted after decoding errors"))
				break
			}
			continue
		}
		e.Properties[name] = v
	}
	runtime.KeepAlive(b)
	return errors.Join(errs...)
}

func decodeValue(typ uint16, b []byte) (any, error) {
	widths := map[uint16]int{3: 1, 4: 1, 5: 2, 6: 2, 7: 4, 8: 4, 9: 8, 10: 8, 11: 4, 12: 8, 13: 4, 15: 16, 17: 8, 18: 16, 20: 4, 21: 8}
	if n, ok := widths[typ]; ok && len(b) != n {
		return nil, fmt.Errorf("TDH type %d requires %d bytes, got %d", typ, n, len(b))
	}
	switch typ {
	case 0:
		return nil, nil
	case 1:
		return utf16String(b)
	case 2:
		return sys.ANSIBytesToString(b)
	case 3:
		return int8(b[0]), nil
	case 4:
		return b[0], nil
	case 5:
		return int16(binary.LittleEndian.Uint16(b)), nil
	case 6:
		return binary.LittleEndian.Uint16(b), nil
	case 7:
		return int32(binary.LittleEndian.Uint32(b)), nil
	case 8, 20:
		return binary.LittleEndian.Uint32(b), nil
	case 9:
		return int64(binary.LittleEndian.Uint64(b)), nil
	case 10, 17, 21:
		return binary.LittleEndian.Uint64(b), nil
	case 11:
		v := math.Float32frombits(binary.LittleEndian.Uint32(b))
		if math.IsInf(float64(v), 0) || math.IsNaN(float64(v)) {
			return nil, fmt.Errorf("non-finite float32 cannot be represented in JSON")
		}
		return v, nil
	case 12:
		v := math.Float64frombits(binary.LittleEndian.Uint64(b))
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return nil, fmt.Errorf("non-finite float64 cannot be represented in JSON")
		}
		return v, nil
	case 13:
		return binary.LittleEndian.Uint32(b) != 0, nil
	case 14:
		return append([]byte(nil), b...), nil
	case 15:
		return (*windows.GUID)(unsafe.Pointer(&b[0])).String(), nil
	case 16, 308:
		if len(b) == 4 {
			return binary.LittleEndian.Uint32(b), nil
		}
		if len(b) == 8 {
			return binary.LittleEndian.Uint64(b), nil
		}
		return nil, fmt.Errorf("invalid pointer size")
	case 18:
		return append([]byte(nil), b...), nil // preserve SYSTEMTIME bytes
	case 19:
		// Validate before decoding; passing an unbounded SID to a native API
		// could read beyond truncated event data. SID authority is big-endian.
		if len(b) < 8 || b[0] != 1 || b[1] > 15 || len(b) != 8+4*int(b[1]) {
			return nil, fmt.Errorf("invalid SID payload")
		}
		authority := uint64(0)
		for _, v := range b[2:8] {
			authority = authority<<8 | uint64(v)
		}
		var s strings.Builder
		s.WriteString("S-1-")
		s.WriteString(strconv.FormatUint(authority, 10))
		for i := 8; i < len(b); i += 4 {
			s.WriteByte('-')
			s.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[i:])), 10))
		}
		return s.String(), nil
	default:
		return nil, fmt.Errorf("unsupported TDH input type %d", typ)
	}
}
