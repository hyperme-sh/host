//go:build linux || darwin

package nativecrash

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Worker capture is initially supported only for the direct macOS Metal worker.
// Containers and confidential guests do not share the Host cleanup authority.
func Supported() bool { return runtime.GOOS == "darwin" }
func SDKLibrary() string {
	return "/usr/local/libexec/hypermesh/crash-sdk/bin/libhypermesh_host_crash.dylib"
}
func private(path string, directory bool) error {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path || !filepath.IsAbs(path) {
		return ErrUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return ErrUnavailable
	}
	if !directory && st.Nlink != 1 {
		return ErrUnavailable
	}
	return nil
}
func installedLibrary(path string) error {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return ErrUnavailable
	}
	for p := path; p != "/"; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil {
			return ErrUnavailable
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return ErrUnavailable
		}
		if p == path && (!info.Mode().IsRegular() || st.Nlink != 1) {
			return ErrUnavailable
		}
	}
	return nil
}
func root() (string, error) {
	account, err := user.LookupId("0")
	if err != nil || account.Uid != "0" {
		return "", ErrUnavailable
	}
	home, err := filepath.EvalSymlinks(account.HomeDir)
	if err != nil {
		return "", ErrUnavailable
	}
	return filepath.Join(home, ".hypermesh-crash-retention", "config"), nil
}
func openPrivate(path string, flags int) (*os.File, error) {
	if private(filepath.Dir(path), true) != nil {
		return nil, ErrUnavailable
	}
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, ErrUnavailable
	}
	return file, nil
}
func lock(directory string) (*os.File, error) {
	file, err := openPrivate(filepath.Join(directory, "health-consent", "crash-capture.lock"), syscall.O_RDWR)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			return file, nil
		}
		if time.Now().After(deadline) {
			file.Close()
			return nil, ErrUnavailable
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func collect(directory, id string) (reports []Report, err error) {
	if !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(id) {
		return nil, ErrUnavailable
	}
	run := filepath.Join(directory, "crash-runs", id)
	if _, e := os.Lstat(run); os.IsNotExist(e) {
		return nil, nil
	}
	if private(directory, true) != nil || private(filepath.Dir(run), true) != nil || private(run, true) != nil {
		return nil, ErrUnavailable
	}
	stop, e := openPrivate(filepath.Join(run, "stop-handler"), syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL)
	if e == nil {
		_, e = stop.Write([]byte("stop"))
		if e == nil {
			e = stop.Sync()
		}
		stop.Close()
		if e != nil {
			return nil, ErrUnavailable
		}
	} else {
		existing, err := openPrivate(filepath.Join(run, "stop-handler"), syscall.O_RDONLY)
		if err != nil {
			return nil, ErrUnavailable
		}
		var value [5]byte
		n, readErr := existing.Read(value[:])
		existing.Close()
		if readErr != nil || n != 4 || string(value[:4]) != "stop" {
			return nil, ErrUnavailable
		}
	}
	capture, e := lock(directory)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer capture.Close()
	// Purge before exposing any report, on success or failed parsing.
	defer func() {
		if removeRun(run) != nil {
			reports = nil
			err = ErrUnavailable
		} else {
			parent, e := os.Open(filepath.Dir(run))
			if e == nil {
				e = parent.Sync()
				parent.Close()
			}
			if e != nil {
				reports = nil
				err = ErrUnavailable
			}
		}
	}()
	entries := 0
	var total int64
	err = filepath.WalkDir(run, func(path string, entry os.DirEntry, walkErr error) error {
		entries++
		if walkErr != nil || entries > 4096 {
			return ErrUnavailable
		}
		relative, e := filepath.Rel(run, path)
		if e != nil || strings.Count(relative, string(os.PathSeparator)) > 8 {
			return ErrUnavailable
		}
		if entry.IsDir() {
			return private(path, true)
		}
		file, e := openPrivate(path, syscall.O_RDONLY)
		if e != nil {
			return e
		}
		defer file.Close()
		if filepath.Ext(path) != ".dmp" {
			return nil
		}
		info, e := file.Stat()
		if e != nil {
			return ErrUnavailable
		}
		total += info.Size()
		if len(reports) >= 5 || total > 160*1024*1024 {
			return ErrUnavailable
		}
		report, e := reduce(file, info.Size())
		if e != nil {
			return e
		}
		reports = append(reports, report)
		return nil
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	return reports, nil
}

// Run adds only the installed capture adapter to the existing native worker.
// A unique parent-generated run ID prevents stale files or PID reuse from being
// mistaken for this worker's crash. No native process output enters the sender.
func Run(ctx context.Context, name string, args []string, statePath string, report func(Report)) ([]byte, error) {
	if !Supported() || os.Geteuid() != 0 || private(statePath, false) != nil || installedLibrary(SDKLibrary()) != nil {
		return nil, ErrUnavailable
	}
	directory, err := root()
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, ErrUnavailable
	}
	nonce[6] = (nonce[6] & 15) | 64
	nonce[8] = (nonce[8] & 63) | 128
	id := fmt.Sprintf("%x-%x-%x-%x-%x", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:])
	cmd := exec.CommandContext(ctx, name, args...)
	for _, item := range os.Environ() {
		key := strings.SplitN(item, "=", 2)[0]
		if strings.HasPrefix(key, "DYLD_") || strings.HasPrefix(key, "LD_") || key == "HYPERMESH_HOST_CRASH_RUN" || key == "HYPERMESH_HOST_CRASH_STATE" {
			continue
		}
		cmd.Env = append(cmd.Env, item)
	}
	cmd.Env = append(cmd.Env, "DYLD_INSERT_LIBRARIES="+SDKLibrary(), "HYPERMESH_HOST_CRASH_RUN="+id, "HYPERMESH_HOST_CRASH_STATE="+statePath)
	output, runErr := cmd.CombinedOutput()
	reports, cleanupErr := collect(directory, id)
	if cleanupErr != nil {
		fmt.Fprintln(os.Stderr, "Host native crash cleanup unavailable")
	}
	if cleanupErr == nil && report != nil {
		for _, event := range reports {
			report(event)
		}
	}
	return output, runErr
}
