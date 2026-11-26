package watchdog

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

const NoticeFile = "recovery-watchdog-notice.json"

type Notice struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func ReadNotice(dir string) *Notice {
	name := filepath.Join(dir, NoticeFile)
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 2048 {
		return nil
	}
	f, err := os.Open(name)
	if err != nil {
		return nil
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil
	}
	var notice Notice
	if json.NewDecoder(io.LimitReader(f, 2048)).Decode(&notice) != nil {
		return nil
	}
	switch notice.Reason {
	case "identity_missing", "retry_exhausted", "state_unavailable":
		return &notice
	default:
		return nil
	}
}
