//go:build darwin

package main

import (
	"github.com/FyberLabs/hypermesh-host/internal/agent"
	"github.com/FyberLabs/hypermesh-host/internal/installer"
)

func configureQualification(cfg *agent.Config) {
	cfg.RunAutomaticNative = installer.RunAutomaticNative
}
