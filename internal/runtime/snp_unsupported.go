//go:build !linux || !amd64

package runtime

func SNPEnabled() bool { return false }
