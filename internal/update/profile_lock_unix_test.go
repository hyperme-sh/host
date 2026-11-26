//go:build linux || darwin

package update

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLockProfileSerializesExecutablesAndRejectsSymlinks(t *testing.T) {
	name := filepath.Join(t.TempDir(), ProfileLockName)
	unlock, err := LockProfile(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockProfile(name); !errors.Is(err, ErrProfileBusy) {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	unlock, err = LockProfile(name)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := os.Rename(name, name+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(name+".old", name); err != nil {
		t.Fatal(err)
	}
	if _, err := LockProfile(name); err == nil {
		t.Fatal("symlink accepted")
	}
}
