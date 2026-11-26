package watchdog

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceMissingBinaryPreservesStateAndRequiresIdleRecheck(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "agent")
	marker := filepath.Join(dir, "device.json")
	if err := os.WriteFile(marker, []byte("original identity"), 0600); err != nil {
		t.Fatal(err)
	}
	payload := []byte("verified agent")
	name := "hypermesh-agent_0.0.213_linux_amd64"
	release := Release{binary: name, checksums: []byte(fmt.Sprintf("%x  %s\n", sha256.Sum256(payload), name))}
	ctx := context.Background()
	idle := func(context.Context) error { return nil }
	if err := release.Replace(ctx, target, []byte("tampered"), idle); err == nil {
		t.Fatal("tampered binary accepted")
	}
	if err := release.Replace(ctx, target, payload, func(context.Context) error {
		return errors.New("workload ownership unknown")
	}); err == nil {
		t.Fatal("replacement proceeded without idle confirmation")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected replacement changed target: %v", err)
	}
	if err := release.Replace(ctx, target, payload, idle); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != string(payload) {
		t.Fatalf("repaired agent: %q %v", got, err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "original identity" {
		t.Fatalf("identity changed: %q %v", got, err)
	}
}
