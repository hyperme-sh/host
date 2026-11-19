//go:build !linux

package installer

import (
	"context"
	"fmt"
	"io"
)

func RunInstallHaloTest(_ context.Context, _ []string, _, diagnostic io.Writer) int {
	fmt.Fprintln(diagnostic, "Halo Vulkan installation requires Linux amd64")
	return 2
}
