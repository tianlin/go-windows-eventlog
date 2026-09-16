//go:build windows

package eventlog

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"github.com/tianlin/go-windows-eventlog/pkg/wineventlog"
	"golang.org/x/sys/windows"
)

type channelProvider struct {
	GUID    windows.GUID
	Name    string
	Channel uint8
}

var channelDLL = windows.NewLazySystemDLL("wevtapi.dll")
var openChannelConfig = channelDLL.NewProc("EvtOpenChannelConfig")
var getChannelConfig = channelDLL.NewProc("EvtGetChannelConfigProperty")

const (
	channelConfigType      = 2
	channelOwningPublisher = 3
	channelPublisherList   = 19
)

func channelProperty(h uintptr, id uint32) (any, error) {
	var size uint32
	r, _, err := getChannelConfig.Call(h, uintptr(id), 0, 0, 0, uintptr(unsafe.Pointer(&size)))
	if r == 0 && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}
	if size < 16 || size > 1<<20 {
		return nil, fmt.Errorf("invalid channel metadata size %d", size)
	}
	buf := make([]byte, size)
	r, _, err = getChannelConfig.Call(h, uintptr(id), 0, uintptr(size), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return nil, err
	}
	v := (*wineventlog.EvtVariant)(unsafe.Pointer(&buf[0]))
	// EvtVariant.Data does not decode string arrays; copy publisher names while
	// the native variant buffer is alive.
	if uint32(v.Type) == 0x81 {
		count := int(v.Count)
		if count > len(buf)/int(unsafe.Sizeof(uintptr(0))) {
			return nil, fmt.Errorf("invalid publisher list")
		}
		ptr := *(*unsafe.Pointer)(unsafe.Pointer(&buf[0]))
		names := make([]string, 0, count)
		for _, p := range unsafe.Slice((**uint16)(ptr), count) {
			names = append(names, windows.UTF16PtrToString(p))
		}
		runtime.KeepAlive(buf)
		return names, nil
	}
	return v.Data(buf)
}

func resolveETWChannel(name string) (uint32, []channelProvider, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, nil, err
	}
	h, _, err := openChannelConfig.Call(0, uintptr(unsafe.Pointer(p)), 0)
	if h == 0 {
		return 0, nil, fmt.Errorf("channel %q: %w", name, err)
	}
	defer wineventlog.EvtHandle(h).Close()
	v, err := channelProperty(h, channelConfigType)
	if err != nil {
		return 0, nil, err
	}
	typ, ok := v.(uint32)
	if !ok {
		return 0, nil, fmt.Errorf("invalid channel type %T", v)
	}
	if typ != 2 && typ != 3 {
		return typ, nil, nil
	}
	v, err = channelProperty(h, channelOwningPublisher)
	if err != nil {
		return typ, nil, err
	}
	owner, ok := v.(string)
	if !ok || owner == "" {
		return typ, nil, fmt.Errorf("channel %q has no owning publisher", name)
	}
	names := []string{owner}
	v, err = channelProperty(h, channelPublisherList)
	if err != nil {
		return typ, nil, err
	}
	if publishers, ok := v.([]string); ok {
		names = append(names, publishers...)
	} else if v != nil {
		return typ, nil, fmt.Errorf("invalid publisher list %T", v)
	}
	out, err := resolveChannelPublishers(name, names, resolvePublisherChannel)
	return typ, out, err
}

func resolveChannelPublishers(name string, names []string, lookup func(string, string) ([]channelProvider, error)) ([]channelProvider, error) {
	seen := map[string]bool{}
	var out []channelProvider
	for _, publisher := range names {
		key := strings.ToLower(publisher)
		if seen[key] {
			continue
		}
		seen[key] = true
		mappings, err := lookup(publisher, name)
		if err != nil {
			return nil, fmt.Errorf("resolve publisher %q: %w", publisher, err)
		}
		if len(mappings) == 0 {
			return nil, fmt.Errorf("publisher %q has no channel ID mapping for %q", publisher, name)
		}
		out = append(out, mappings...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no manifest provider/channel ID mapping for %q", name)
	}
	return out, nil
}

func resolvePublisherChannel(publisher, name string) ([]channelProvider, error) {
	md, err := wineventlog.NewPublisherMetadata(0, publisher, 0)
	if err != nil {
		return nil, err
	}
	defer md.Close()
	guid, err := md.PublisherGUID()
	if err != nil {
		return nil, err
	}
	if guid == (windows.GUID{}) {
		return nil, fmt.Errorf("missing provider GUID")
	}
	v, err := wineventlog.EvtGetPublisherMetadataProperty(md.Handle, wineventlog.EvtPublisherMetadataChannelReferences)
	if err != nil {
		return nil, err
	}
	array, ok := v.(wineventlog.EvtObjectArrayPropertyHandle)
	if !ok {
		return nil, fmt.Errorf("invalid channel references %T", v)
	}
	defer array.Close()
	count, err := wineventlog.EvtGetObjectArraySize(array)
	if err != nil {
		return nil, err
	}
	var out []channelProvider
	for i := uint32(0); i < count; i++ {
		path, err := wineventlog.EvtGetObjectArrayProperty(array, wineventlog.EvtPublisherMetadataChannelReferencePath, i)
		if err != nil {
			return nil, err
		}
		s, ok := path.(string)
		if !ok {
			return nil, fmt.Errorf("invalid channel reference path %T", path)
		}
		if !strings.EqualFold(s, name) {
			continue
		}
		id, err := wineventlog.EvtGetObjectArrayProperty(array, wineventlog.EvtPublisherMetadataChannelReferenceID, i)
		if err != nil {
			return nil, err
		}
		n, ok := id.(uint32)
		if !ok || n > 255 || n == 0 {
			return nil, fmt.Errorf("invalid channel reference ID %v", id)
		}
		out = append(out, channelProvider{GUID: guid, Name: publisher, Channel: uint8(n)})
	}
	return out, nil
}
