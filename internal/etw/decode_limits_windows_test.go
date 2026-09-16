//go:build windows && (amd64 || arm64)

package etw

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"testing"
)

func TestTDHEmptyMetadata(t *testing.T) {
	// A valid zero-property metadata header must not index byte 112.
	b := make([]byte, 112)
	if err := decodeMetadata(&eventRecord{}, &Event{}, b); err != nil {
		t.Fatal(err)
	}
}

func TestTDHGlobalDecodeBudget(t *testing.T) {
	b := decodeBudget{values: 10, bytes: 10}
	if err := b.takeValues(6); err != nil {
		t.Fatal(err)
	}
	if err := b.takeValues(6); err == nil {
		t.Fatal("nested arrays bypassed event budget")
	}
	if err := b.takeBytes(11); err == nil {
		t.Fatal("payload exceeded budget")
	}
}

func TestTDHLimitsMetadataErrorAmplification(t *testing.T) {
	const count = 4096
	nameOffset := 112 + 24*count
	b := make([]byte, nameOffset+20000)
	binary.LittleEndian.PutUint32(b[100:], count)
	binary.LittleEndian.PutUint32(b[104:], count)
	for i := 0; i < count; i++ {
		off := 112 + i*24
		binary.LittleEndian.PutUint32(b[off:], 128)
		binary.LittleEndian.PutUint32(b[off+4:], uint32(nameOffset))
	}
	for i := nameOffset; i < len(b)-2; i += 2 {
		b[i] = 'x'
	}
	err := decodeMetadata(&eventRecord{}, &Event{}, b)
	if err == nil {
		t.Fatal("custom schema accepted")
	}
	if len(err.Error()) > 8192 {
		t.Fatalf("unbounded metadata error amplification: %d bytes", len(err.Error()))
	}
}

func TestTDHFloatJSON(t *testing.T) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, math.Float64bits(math.Inf(1)))
	v, err := decodeValue(12, b)
	if err == nil {
		if _, err = json.Marshal(v); err != nil {
			t.Fatal("decoded value cannot be serialized:", err)
		}
	}
}

func TestTDHSID(t *testing.T) {
	// S-1-5-18 (LocalSystem).
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	v, err := decodeValue(19, sid)
	if err != nil || v != "S-1-5-18" {
		t.Fatalf("SID=%v err=%v", v, err)
	}
	if _, err := decodeValue(19, sid[:8]); err == nil {
		t.Fatal("truncated SID accepted")
	}
}
