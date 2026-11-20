package update

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRevertOnlyRetainedSignedTarget(t *testing.T) {
	for _, scenario := range []string{"ok", "signature", "channel", "missing", "tampered", "busy", "restart", "bad", "newer"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			proof := evidenceFixture()
			cfg := Config{Channel: "test", Arch: "arm64", CurrentBuild: 31, CurrentVersion: "0.0.31", BinaryPath: filepath.Join(dir, "agent"), PubKeyPath: filepath.Join(dir, "key"), MarkerPath: filepath.Join(dir, MarkerName)}
			for path, data := range map[string]string{cfg.BinaryPath: "current", cfg.BinaryPath + ".pre-old": "agent", cfg.PubKeyPath: "key"} {
				if err := os.WriteFile(path, []byte(data), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := WriteEvidence(dir, proof); err != nil {
				t.Fatal(err)
			}
			restarted := false
			hooks := Hooks{Verify: func([]byte, []byte, []byte) error { return nil }, Restart: func(context.Context) error { restarted = true; return nil }}
			switch scenario {
			case "signature":
				hooks.Verify = func([]byte, []byte, []byte) error { return fmt.Errorf("bad signature") }
			case "channel":
				cfg.Channel = "prod"
			case "missing":
				os.Remove(cfg.BinaryPath + ".pre-old")
			case "tampered":
				os.WriteFile(cfg.BinaryPath+".pre-old", []byte("modified"), 0700)
			case "busy":
				hooks.StillBusy = func() bool { return true }
			case "restart":
				hooks.Restart = func(context.Context) error { return fmt.Errorf("restart failed") }
			case "bad":
				cfg.BadBuild = 30
			case "newer":
				cfg.CurrentBuild = 29
			}
			plan, err := Revert(context.Background(), cfg, proof.SHA256, hooks)
			data, _ := os.ReadFile(cfg.BinaryPath)
			if scenario == "ok" {
				if err != nil || !restarted || plan.Action != ActionInstall || string(data) != "agent" {
					t.Fatalf("%+v %v %q", plan, err, data)
				}
				if bad, err := ReadBadBuild(filepath.Join(dir, BadName)); err != nil || bad != 31 {
					t.Fatal("forward update could reinstall reverted build")
				}
			} else {
				if scenario != "busy" && err == nil {
					t.Fatal("invalid revert accepted")
				}
				if restarted || string(data) != "current" {
					t.Fatal("rejected revert replaced running binary")
				}
			}
		})
	}
}

func TestFileSHA256RefusesNonFiles(t *testing.T) {
	if _, err := FileSHA256(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := Revert(context.Background(), Config{}, strings.Repeat("z", 64), Hooks{}); err == nil {
		t.Fatal("invalid target accepted")
	}
}
