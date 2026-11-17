//go:build !linux && !darwin

package nativecrash

import "context"

func Supported() bool { return false }
func Run(context.Context, string, []string, string, func(Report)) ([]byte, error) {
	return nil, ErrUnavailable
}
