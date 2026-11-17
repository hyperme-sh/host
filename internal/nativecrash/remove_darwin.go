//go:build darwin

package nativecrash

import "os"

func removeRun(run string) error { return os.RemoveAll(run) }
