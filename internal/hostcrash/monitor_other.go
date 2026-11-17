//go:build !linux && !darwin

package hostcrash

import "time"

// MonitorSupported is false where the private Go runtime pipe is not implemented.
func MonitorSupported() bool               { return false }
func BindChild() (bool, error)             { return false, nil }
func Monitor(func(time.Time)) (int, error) { return 0, ErrUnavailable }
