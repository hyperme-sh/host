// Package nativecrash owns the fixed-schema boundary for local worker dumps.
package nativecrash

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

var ErrUnavailable = errors.New("native crash reporting unavailable")

const maxDump = 32 * 1024 * 1024

type Report struct {
	Code     string
	Captured time.Time
}

// reduce reads only fixed numeric header/exception fields. It never allocates or
// returns process memory, string streams, module names, paths or stack content.
func reduce(file io.ReaderAt, size int64) (Report, error) {
	if size < 32 || size > maxDump {
		return Report{}, ErrUnavailable
	}
	word := func(offset int64) (uint32, error) {
		var raw [4]byte
		_, err := file.ReadAt(raw[:], offset)
		return binary.LittleEndian.Uint32(raw[:]), err
	}
	signature, e := word(0)
	if e != nil || signature != 0x504d444d {
		return Report{}, ErrUnavailable
	}
	version, e := word(4)
	if e != nil || version&0xffff != 0xa793 {
		return Report{}, ErrUnavailable
	}
	count, e := word(8)
	if e != nil || count < 1 || count > 128 {
		return Report{}, ErrUnavailable
	}
	directory, e := word(12)
	if e != nil || directory < 32 || int64(directory)+int64(count)*12 > size {
		return Report{}, ErrUnavailable
	}
	timestamp, e := word(20)
	if e != nil || timestamp == 0 {
		return Report{}, ErrUnavailable
	}
	found := false
	code := "native_crash"
	for i := uint32(0); i < count; i++ {
		at := int64(directory) + int64(i)*12
		kind, e := word(at)
		if e != nil {
			return Report{}, ErrUnavailable
		}
		length, e := word(at + 4)
		if e != nil {
			return Report{}, ErrUnavailable
		}
		offset, e := word(at + 8)
		if e != nil || int64(offset)+int64(length) > size {
			return Report{}, ErrUnavailable
		}
		if kind != 6 {
			continue
		}
		if found || length < 168 || offset < 32 || (int64(offset) < int64(directory)+int64(count)*12 && int64(offset)+int64(length) > int64(directory)) {
			return Report{}, ErrUnavailable
		}
		found = true
		value, e := word(int64(offset) + 8)
		if e != nil {
			return Report{}, ErrUnavailable
		}
		switch value {
		case 0xc0000005:
			code = "invalid_memory_access"
		case 0xc000001d:
			code = "illegal_instruction"
		case 0xc0000094, 0xc000008e:
			code = "arithmetic_fault"
		}
	}
	if !found {
		return Report{}, ErrUnavailable
	}
	return Report{Code: code, Captured: time.Unix(int64(timestamp), 0).UTC()}, nil
}
