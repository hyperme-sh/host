//go:build linux || darwin

package update

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ErrProfileBusy means a different local operation owns the profile.
const ProfileLockName = "software-update.lock"

var ErrProfileBusy = errors.New("Host update profile busy")

// LockProfile serializes executable changes in an installer-owned state directory.
func LockProfile(path string) (func(), error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	var info unix.Stat_t
	err = unix.Fstat(fd, &info)
	if err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&0777 != 0600 ||
		info.Uid != uint32(os.Geteuid()) || info.Nlink != 1 {
		unix.Close(fd)
		return nil, fmt.Errorf("unsafe Host update lock")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrProfileBusy
		}
		return nil, err
	}
	return func() { _ = unix.Close(fd) }, nil
}
