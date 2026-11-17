//go:build windows

package main

import (
	"github.com/FyberLabs/hypermesh-host/internal/windowsfeedback"
	"os"
)

func main() {
	if len(os.Args) != 1 || windowsfeedback.Run() != nil {
		os.Exit(1)
	}
}
