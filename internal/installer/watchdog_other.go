//go:build !linux && !darwin

package installer

import (
	"context"
	"fmt"
	"io"
)

func RunWatchdog(_ context.Context, _ []string, _, diagnostic io.Writer) int {
	fmt.Fprintln(diagnostic, "recovery watchdog is unavailable on this platform")
	return 2
}
