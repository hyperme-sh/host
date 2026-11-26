//go:build !linux && !darwin

package update

import "errors"

const ProfileLockName = "software-update.lock"

var ErrProfileBusy = errors.New("Host update profile busy")

func LockProfile(string) (func(), error) {
	return nil, errors.New("Host update profile locking is unavailable on this platform")
}
