//go:build linux

package visorbridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func (b *Bridge) serviceExecutable() (*os.File, string, error) {
	if _, err := b.serviceBinding(); err != nil {
		return nil, "", err
	}
	path := b.config.ServiceControl.Executable
	if trustedExecutable(path) != nil {
		return nil, "", refused
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", refused
	}
	file := os.NewFile(uintptr(fd), path)
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, "", refused
	}
	owner, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !stat.Mode().IsRegular() || stat.Mode().Perm()&0022 != 0 || stat.Size() > 64<<20 {
		file.Close()
		return nil, "", refused
	}
	sum := sha256.New()
	if _, err = io.Copy(sum, io.LimitReader(file, 64<<20)); err != nil {
		file.Close()
		return nil, "", refused
	}
	return file, hex.EncodeToString(sum.Sum(nil)), nil
}
func (b *Bridge) serviceContext() (map[string]any, error) {
	file, hash, err := b.serviceExecutable()
	if err != nil {
		return nil, err
	}
	file.Close()
	binding, err := b.serviceBinding()
	if err != nil {
		return nil, err
	}
	c := b.config.ServiceControl
	return map[string]any{"uid": c.UID, "units": c.Units, "executable": c.Executable, "executable_sha256": hash, "controller_binding_sha256": binding}, nil
}
func (b *Bridge) restartService(ctx context.Context, action, result []byte) ([]byte, error) {
	var review struct {
		Reserved  bool            `json:"reserved"`
		Permitted bool            `json:"permitted"`
		Expires   float64         `json:"expires_at"`
		Action    json.RawMessage `json:"action"`
	}
	if json.Unmarshal(result, &review) != nil || !review.Reserved || !review.Permitted || review.Expires <= float64(time.Now().UnixNano())/1e9 {
		return nil, refused
	}
	file, hash, err := b.serviceExecutable()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	args, err := b.serviceCall(action, hash)
	if err != nil {
		return nil, err
	}
	var returned, requested any
	if json.Unmarshal(review.Action, &returned) != nil || json.Unmarshal(action, &requested) != nil {
		return nil, refused
	}
	a, _ := json.Marshal(returned)
	r, _ := json.Marshal(requested)
	if string(a) != string(r) {
		return nil, refused
	}
	var scope struct {
		Limits struct {
			Seconds uint32 `json:"timeout_seconds"`
		} `json:"limits"`
	}
	if json.Unmarshal(action, &scope) != nil || scope.Limits.Seconds == 0 || scope.Limits.Seconds > 30 {
		return nil, refused
	}
	deadline := serviceDeadline(review.Expires, scope.Limits.Seconds, time.Now())
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	cmd := serviceCommand(ctx, b.config.ServiceControl, args.Unit, file)
	if ctx.Err() != nil || cmd.Run() != nil {
		return nil, refused
	}
	return json.Marshal(map[string]any{"completed": true, "unit": args.Unit, "review": json.RawMessage(result)})
}

// The driver has no caller-controlled command, environment, UID or flags.
func serviceCommand(ctx context.Context, c *UserServiceConfig, unit string, file *os.File) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "--user", "--no-ask-password", "restart", "--", unit)
	cmd.ExtraFiles = []*os.File{file}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.UID, Gid: c.GID, Groups: []uint32{}}}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent", fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", c.UID), fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", c.UID)}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	return cmd
}

func serviceDeadline(expires float64, seconds uint32, now time.Time) time.Time {
	lease := time.Unix(0, int64(expires*1e9))
	limit := now.Add(time.Duration(seconds) * time.Second)
	if limit.Before(lease) {
		return limit
	}
	return lease
}
