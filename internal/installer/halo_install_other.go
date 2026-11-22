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

func RunInstallForumTest(_ context.Context, _ []string, _, diagnostic io.Writer) int {
	fmt.Fprintln(diagnostic, "J4012 forum TEST installation requires Linux arm64")
	return 2
}
