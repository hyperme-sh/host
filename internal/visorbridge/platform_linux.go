//go:build linux

package visorbridge

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func trustedExecutable(path string) error    { return trustedPath(path, true) }
func trustedConfiguration(path string) error { return trustedPath(path, false) }
func peerUID(conn net.Conn) (uint32, error) {
	if wrapped, ok := conn.(*peerConnection); ok {
		conn = wrapped.Conn
	}
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, refused
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return 0, refused
	}
	var cred *syscall.Ucred
	var peerErr error
	if err = raw.Control(func(fd uintptr) {
		cred, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || peerErr != nil || cred == nil {
		return 0, refused
	}
	return cred.Uid, nil
}
func controllerStateDir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return refused
	}
	for dir := path; ; dir = filepath.Dir(dir) {
		st, err := os.Lstat(dir)
		if err != nil {
			return refused
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || (st.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && st.Mode()&os.ModeSticky != 0)) {
			return refused
		}
		if dir == path && (stat.Uid != uint32(os.Geteuid()) || st.Mode().Perm() != 0700) {
			return refused
		}
		if dir == "/" {
			break
		}
	}
	return nil
}
