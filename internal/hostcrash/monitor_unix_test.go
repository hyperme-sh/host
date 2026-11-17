//go:build linux || darwin

package hostcrash

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestMonitorHelper(t *testing.T) {
	mode := os.Getenv("HYPERMESH_CRASH_UNIT_MODE")
	if mode == "" {
		return
	}
	child, err := BindChild()
	if err != nil {
		os.Exit(91)
	}
	if child {
		fmt.Fprintln(os.Stderr, "application-log-preserved")
		switch mode {
		case "panic":
			go func() { panic("RAW_SECRET_CANARY") }()
			select {}
		case "ordinary":
			os.Exit(2)
		case "normal":
			os.Exit(0)
		}
	}
	code, err := Monitor(func(at time.Time) {
		if at.IsZero() {
			os.Exit(92)
		}
		fmt.Println("fixed-crash-event")
	})
	if err != nil {
		os.Exit(93)
	}
	os.Exit(code)
}
func TestMonitorRuntimeBoundary(t *testing.T) {
	for _, mode := range []string{"panic", "ordinary", "normal"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMonitorHelper$")
			cmd.Env = append(os.Environ(), "HYPERMESH_CRASH_UNIT_MODE="+mode)
			output, err := cmd.CombinedOutput()
			if bytes.Contains(output, []byte("RAW_SECRET_CANARY")) {
				t.Fatal("raw panic leaked")
			}
			if !bytes.Contains(output, []byte("application-log-preserved")) {
				t.Fatalf("logging lost: %s", output)
			}
			if bytes.Contains(output, []byte("fixed-crash-event")) != (mode == "panic") {
				t.Fatalf("wrong crash classification: %s", output)
			}
			if (err == nil) != (mode == "normal") {
				t.Fatal("exit changed", err)
			}
		})
	}
}
