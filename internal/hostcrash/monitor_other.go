//go:build !linux && !darwin

package hostcrash

import "time"

func BindChild() (bool, error)             { return false, nil }
func Monitor(func(time.Time)) (int, error) { return 0, ErrUnavailable }
