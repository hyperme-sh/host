package watchdog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckpointRetainsBudgetAndRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	checkpoint := Checkpoint{Dir: dir}
	if state, err := checkpoint.Load(); err != nil || state != (State{}) {
		t.Fatalf("empty checkpoint: %+v %v", state, err)
	}
	want := State{Attempts: 2, NextAttempt: time.Now().UTC()}
	if err := checkpoint.Save(want); err != nil {
		t.Fatal(err)
	}
	reopened := Checkpoint{Dir: dir}
	if state, err := reopened.Load(); err != nil || state != want {
		t.Fatalf("reopened checkpoint: %+v %v", state, err)
	}
	p := filepath.Join(dir, checkpointName)
	if err := os.Rename(p, p+".backup"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p+".backup", p); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Load(); err == nil {
		t.Fatal("followed checkpoint symlink")
	}
}
