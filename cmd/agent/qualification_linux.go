//go:build linux

package main

import "github.com/FyberLabs/hypermesh-host/internal/agent"
import "github.com/FyberLabs/hypermesh-host/internal/installer"

func configureQualification(cfg *agent.Config) {
	cfg.RunPendingQualification = installer.RunPendingQualification
}
