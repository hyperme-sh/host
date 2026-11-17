//go:build windows

package main

import (
	"github.com/FyberLabs/hypermesh-host/internal/windowscrash"
	"os"
)

func main() {
	if len(os.Args) != 1 || windowscrash.Run() != nil {
		os.Exit(1)
	}
}
