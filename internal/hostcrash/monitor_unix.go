//go:build linux || darwin

package hostcrash

import (
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const childMarker = "HYPERMESH_INTERNAL_CRASH_CHILD"

// MonitorSupported reports whether this build can supervise Go runtime crashes.
func MonitorSupported() bool { return true }

// BindChild installs the Go runtime's private crash pipe in the reexecuted
// agent. No normal stderr, returned error or exit status is a crash assertion.
func BindChild() (bool, error) {
	if os.Getenv(childMarker) != "1" {
		return false, nil
	}
	if os.Unsetenv(childMarker) != nil {
		return true, ErrUnavailable
	}
	f := os.NewFile(3, "runtime-crash-pipe")
	if f == nil {
		return true, ErrUnavailable
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return true, ErrUnavailable
	}
	logs := os.NewFile(4, "application-log")
	if logs == nil {
		return true, ErrUnavailable
	}
	if _, err := logs.Stat(); err != nil {
		logs.Close()
		return true, ErrUnavailable
	}
	syscall.CloseOnExec(4)
	os.Stderr = logs
	if debug.SetCrashOutput(f, debug.CrashOptions{}) != nil {
		return true, ErrUnavailable
	}
	return true, nil
}

// Monitor stays alive as the service main process until the child exits and the
// bounded report attempt finishes. Raw runtime bytes are drained and discarded;
// no raw file, buffer, queue or log is created here.
func Monitor(report func(time.Time)) (int, error) {
	executable, err := os.Executable()
	if err != nil {
		return 0, ErrUnavailable
	}
	read, write, err := os.Pipe()
	if err != nil {
		return 0, ErrUnavailable
	}
	defer read.Close()
	defer write.Close()
	cmd := exec.Command(executable, os.Args[1:]...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, childMarker+"=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, childMarker+"=1")
	cmd.ExtraFiles = []*os.File{write, os.Stderr}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	// Runtime writes directly to fd 2; discard its duplicate raw traceback.
	// Application logging uses the separate inherited descriptor through os.Stderr.
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer null.Close()
	cmd.Stderr = null
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	if cmd.Start() != nil {
		return 0, ErrUnavailable
	}
	write.Close()
	var crashed atomic.Bool
	var captured time.Time
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		var scratch [4096]byte
		for {
			n, e := read.Read(scratch[:])
			if n > 0 && !crashed.Swap(true) {
				captured = time.Now()
			}
			clear(scratch[:])
			if e != nil {
				return
			}
		}
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	for {
		select {
		case sig := <-signals:
			_ = cmd.Process.Signal(sig)
		case <-exited:
			// A descendant cannot keep the service alive by retaining an inherited pipe.
			select {
			case <-drained:
			case <-time.After(time.Second):
				read.Close()
				<-drained
			}
			if crashed.Load() && report != nil {
				report(captured)
			}
			if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				return 128 + int(status.Signal()), nil
			}
			return cmd.ProcessState.ExitCode(), nil
		}
	}
}
