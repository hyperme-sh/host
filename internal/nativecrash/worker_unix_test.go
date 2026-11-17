//go:build linux || darwin

package nativecrash

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func fixture(t *testing.T) (string, string, string) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("mode")
	}
	id := "11111111-1111-4111-8111-111111111111"
	run := filepath.Join(directory, "crash-runs", id)
	for _, path := range []string{filepath.Join(directory, "health-consent"), run, filepath.Join(run, "database", "pending")} {
		if os.MkdirAll(path, 0700) != nil {
			t.Fatal("mkdir")
		}
	}
	if os.WriteFile(filepath.Join(directory, "health-consent", "crash-capture.lock"), nil, 0600) != nil {
		t.Fatal("lock")
	}
	return directory, id, run
}
func TestRawRemovalPrecedesReport(t *testing.T) {
	directory, id, run := fixture(t)
	path := filepath.Join(run, "database", "pending", "22222222-2222-4222-8222-222222222222.dmp")
	if os.WriteFile(path, dump(), 0600) != nil {
		t.Fatal("write")
	}
	reports, err := collect(directory, id)
	if err != nil || len(reports) != 1 {
		t.Fatal(reports, err)
	}
	if _, err = os.Lstat(run); !os.IsNotExist(err) {
		t.Fatal("raw run remains")
	}
}
func TestFailedReductionPurgesAndDoesNotFollowLinks(t *testing.T) {
	for _, kind := range []string{"invalid", "linked"} {
		t.Run(kind, func(t *testing.T) {
			directory, id, run := fixture(t)
			path := filepath.Join(run, "database", "pending", "bad.dmp")
			target := filepath.Join(directory, "outside")
			if os.WriteFile(target, []byte("private"), 0600) != nil {
				t.Fatal("target")
			}
			if kind == "linked" {
				if os.Symlink(target, path) != nil {
					t.Fatal("link")
				}
			} else {
				if os.WriteFile(path, []byte("bad"), 0600) != nil {
					t.Fatal("write")
				}
			}
			reports, err := collect(directory, id)
			if err == nil || len(reports) != 0 {
				t.Fatal("invalid report")
			}
			if _, err = os.Lstat(run); !os.IsNotExist(err) {
				t.Fatal("run remains")
			}
			if raw, e := os.ReadFile(target); e != nil || string(raw) != "private" {
				t.Fatal("outside target changed")
			}
		})
	}
}

func TestCrashFIFOIsRefusedWithoutAWriter(t *testing.T) {
	directory, id, run := fixture(t)
	fifo := filepath.Join(run, "database", "pending", "blocked.dmp")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	// Exercise the open itself as well as the walk's file-type filter.
	done := make(chan error, 1)
	go func() {
		f, err := openPrivate(fifo, syscall.O_RDONLY)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO open blocked")
	}
	reports, err := collect(directory, id)
	if err == nil || len(reports) != 0 {
		t.Fatal("FIFO report accepted")
	}
	if _, err := os.Lstat(run); !os.IsNotExist(err) {
		t.Fatal("FIFO run not purged")
	}
}
func TestCancelledCollectionStillPurgesRawRun(t *testing.T) {
	directory, id, run := fixture(t)
	if err := os.WriteFile(filepath.Join(run, "database", "pending", "private.dmp"), dump(), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reports, err := collectContext(ctx, directory, id)
	if err == nil || len(reports) != 0 {
		t.Fatal("cancelled collection emitted a report")
	}
	if _, err := os.Lstat(run); !os.IsNotExist(err) {
		t.Fatal("cancelled raw run not purged")
	}
}

type forbiddenReader struct{ t *testing.T }

func (r forbiddenReader) ReadAt([]byte, int64) (int, error) {
	r.t.Fatal("cancelled collection read raw data")
	return 0, nil
}
func TestCancelledReducerDoesNotReadRawData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reduce(collectionReader{context: ctx, file: forbiddenReader{t}}, int64(len(dump()))); err == nil {
		t.Fatal("cancelled reduction accepted")
	}
}
