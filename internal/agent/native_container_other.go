//go:build !linux

package agent

import "github.com/FyberLabs/hypermesh-host/internal/runtime"

func nativeContainer(Config) runtime.ContainerCapture { return nil }
