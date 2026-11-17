//go:build linux || darwin

package hostcrash

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
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
		case "stall":
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
	for _, mode := range []string{"panic", "ordinary", "normal", "stall"} {
		t.Run(mode, func(t *testing.T) {
			limit := 10 * time.Second
			if mode == "stall" {
				limit = time.Second
			}
			started := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMonitorHelper$")
			cmd.Env = append(os.Environ(), "HYPERMESH_CRASH_UNIT_MODE="+mode)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.WaitDelay = time.Second
			cmd.Cancel = func() error {
				err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				if err == syscall.ESRCH {
					return os.ErrProcessDone
				}
				return err
			}
			defer func() {
				if cmd.Process != nil {
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				}
			}()
			output, err := cmd.CombinedOutput()
			if mode == "stall" && time.Since(started) > 5*time.Second {
				t.Fatal("stalled process tree exceeded bounded wait")
			}
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
