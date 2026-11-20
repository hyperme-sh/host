package update

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRevertOnlyRetainedSignedTarget(t *testing.T) {
	for _, scenario := range []string{"ok", "higher-bad-build", "legacy-control", "signature", "channel", "missing", "tampered", "busy", "restart", "bad", "newer"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			proof := evidenceFixture()
			var manifest Manifest
			if err := json.Unmarshal(proof.Manifest, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest.SoftwareControlProtocol = 1
			if scenario == "legacy-control" {
				manifest.SoftwareControlProtocol = 0
			}
			proof.Manifest, _ = json.Marshal(manifest)
			mh, bh := sha256.Sum256(proof.Manifest), sha256.Sum256([]byte("agent"))
			proof.Checksums = []byte(fmt.Sprintf("%x  release.json\n%x  %s\n", mh, bh, proof.Binary))
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
			case "higher-bad-build":
				cfg.BadBuild = 32
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
			if scenario == "ok" || scenario == "higher-bad-build" {
				if err != nil || !restarted || plan.Action != ActionInstall || string(data) != "agent" {
					t.Fatalf("%+v %v %q", plan, err, data)
				}
				if bad, err := ReadBadBuild(filepath.Join(dir, BadName)); err != nil || bad != max(cfg.CurrentBuild, cfg.BadBuild) {
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

func TestFailedRevertStartupPreservesHigherBadBuild(t *testing.T) {
	for _, shell := range []bool{false, true} {
		t.Run(fmt.Sprint(shell), func(t *testing.T) {
			dir := t.TempDir()
			dest := filepath.Join(dir, "agent")
			backup := dest + ".pre-old"
			os.WriteFile(dest, []byte("bad"), 0755)
			os.WriteFile(backup, []byte("working"), 0755)
			marker := filepath.Join(dir, MarkerName)
			if err := WriteBadBuild(filepath.Join(dir, BadName), 32, "known-bad"); err != nil {
				t.Fatal(err)
			}
			if err := WriteMarker(marker, Marker{Binary: dest, Backup: backup, Version: "0.0.30", Build: 30, Deadline: time.Unix(1, 0)}); err != nil {
				t.Fatal(err)
			}
			if shell {
				cmd := exec.Command("/bin/sh", filepath.Join("..", "..", "deploy", "lib", "update-rollback"))
				cmd.Env = append(os.Environ(), "HYPERMESH_STATE_DIR="+dir)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s %v", out, err)
				}
			} else {
				Watch(context.Background(), WatchConfig{MarkerPath: marker, Interval: time.Millisecond, HeartbeatOK: func() uint64 { return 0 }, Now: func() time.Time { return time.Unix(2, 0) }, Rollback: func() error { return RollbackFile(dest, backup) }, Exit: func(int) {}})
			}
			if got, err := ReadBadBuild(filepath.Join(dir, BadName)); err != nil || got != 32 {
				t.Fatalf("threshold=%d err=%v", got, err)
			}
			if raw, err := os.ReadFile(dest); err != nil || string(raw) != "working" {
				t.Fatal("rollback failed", err)
			}
		})
	}
}
