package nativecrash

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func dump() []byte {
	raw := make([]byte, 212)
	word := func(at int, value uint32) { binary.LittleEndian.PutUint32(raw[at:at+4], value) }
	word(0, 0x504d444d)
	word(4, 0xa793)
	word(8, 1)
	word(12, 32)
	word(20, uint32(time.Now().Unix()))
	word(32, 6)
	word(36, 168)
	word(40, 44)
	word(52, 0xc0000005)
	return append(raw, []byte("PROMPT_SECRET_FILE_SERIAL_CANARY")...)
}
func TestFixedNumericDumpBoundary(t *testing.T) {
	raw := dump()
	report, err := reduce(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || report.Code != "invalid_memory_access" {
		t.Fatal(report, err)
	}
	for _, test := range []struct {
		at    int
		value uint32
	}{{0, 0}, {8, 129}, {12, 0xffffffff}, {36, 0xffffffff}, {40, 32}, {20, 0}} {
		changed := append([]byte(nil), raw...)
		binary.LittleEndian.PutUint32(changed[test.at:test.at+4], test.value)
		if _, err := reduce(bytes.NewReader(changed), int64(len(changed))); err == nil {
			t.Fatal("invalid dump accepted", test.at)
		}
	}
	binary.LittleEndian.PutUint32(raw[52:56], 0xdeadbeef)
	report, err = reduce(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || report.Code != "native_crash" {
		t.Fatal(report, err)
	}
	if _, err := reduce(bytes.NewReader(raw), maxDump+1); err == nil {
		t.Fatal("oversize")
	}
}
