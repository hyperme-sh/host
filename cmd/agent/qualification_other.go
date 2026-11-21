//go:build !linux && !darwin

package main

import "github.com/FyberLabs/hypermesh-host/internal/agent"

func configureQualification(cfg *agent.Config) {}
