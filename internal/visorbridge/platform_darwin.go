//go:build darwin

package visorbridge

import (
	"golang.org/x/sys/unix"
	"net"
)

// macOS exposes only the explicitly configured feedback broker.
func trustedExecutable(string) error    { return refused }
func trustedConfiguration(string) error { return refused }
func controllerStateDir(string) error   { return refused }

func peerUID(conn net.Conn) (uint32, error) {
	if wrapped, ok := conn.(*peerConnection); ok {
		conn = wrapped.Conn
	}
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, refused
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return 0, refused
	}
	var cred *unix.Xucred
	var peerErr error
	err = raw.Control(func(fd uintptr) {
		cred, peerErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if err != nil || peerErr != nil || cred == nil || cred.Version != 0 {
		return 0, refused
	}
	return cred.Uid, nil
}
