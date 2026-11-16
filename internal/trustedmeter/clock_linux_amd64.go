package trustedmeter

import (
	"encoding/binary"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// SNPClock uses the measured Linux kernel's raw TSC clock. Its constructor
// refuses ordinary SNP guests without Secure TSC. The independent verifier
// still has to approve the kernel, boot profile and clock-rate allowance.
// It is not an attestation API and cannot qualify an ordinary host by itself.
type SNPClock struct{}

func secureClockStatus(status uint64, source string) error {
	// Linux arch/x86/include/asm/msr-index.h: SNP enabled bit 2,
	// SNP Secure TSC bit 11 in MSR_AMD64_SEV (0xc0010131).
	if status&(1<<2|1<<11) != (1<<2|1<<11) || strings.TrimSpace(source) != "tsc" {
		return ErrDisputed
	}
	return nil
}
func checkSecureClock() error {
	f, err := os.Open("/dev/cpu/0/msr")
	if err != nil {
		return ErrDisputed
	}
	defer f.Close()
	var raw [8]byte
	if _, err = f.ReadAt(raw[:], 0xc0010131); err != nil {
		return ErrDisputed
	}
	source, err := os.ReadFile("/sys/devices/system/clocksource/clocksource0/current_clocksource")
	if err != nil {
		return ErrDisputed
	}
	return secureClockStatus(binary.LittleEndian.Uint64(raw[:]), string(source))
}
func NewSNPClock() (*SNPClock, error) {
	if err := checkSecureClock(); err != nil {
		return nil, err
	}
	c := &SNPClock{}
	if _, err := c.Sample(); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *SNPClock) Sample() (time.Duration, error) {
	if err := checkSecureClock(); err != nil {
		return 0, err
	}
	var value syscall.Timespec
	// CLOCK_MONOTONIC_RAW avoids NTP adjustments. No wall-time fallback.
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 4, uintptr(unsafe.Pointer(&value)), 0)
	if errno != 0 || value.Sec < 0 || value.Nsec < 0 || value.Nsec >= 1e9 || value.Sec > ((1<<63-1)-value.Nsec)/1e9 {
		return 0, ErrDisputed
	}
	return time.Duration(value.Sec*1e9 + value.Nsec), nil
}
