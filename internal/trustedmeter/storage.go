package trustedmeter

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

const (
	MaxRequestJournalBytes int64 = 8 << 20
	MaxLeaseJournalBytes   int64 = 64 << 20
	MaxLeaseJournalFiles         = 256
	MaxHostJournalBytes    int64 = 256 << 20
	MaxHostJournalFiles          = 2048
)

func journalUsage(dir string, fileLimit int, byteLimit int64) (int, int64, error) {
	f, err := os.Open(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	entries, err := f.Readdir(fileLimit + 1)
	if err != nil && err != io.EOF {
		return 0, 0, err
	}
	if len(entries) > fileLimit {
		return 0, 0, ErrInvalid
	}
	var total int64
	for _, entry := range entries {
		if !entry.Mode().IsRegular() || entry.Size() < 0 || entry.Size() > byteLimit-total {
			return 0, 0, ErrInvalid
		}
		total += entry.Size()
	}
	return len(entries), total, nil
}
func reserveRequestJournal(dir string) error {
	files, size, err := journalUsage(dir, MaxLeaseJournalFiles, MaxLeaseJournalBytes)
	if err != nil {
		return err
	}
	if files >= MaxLeaseJournalFiles-1 || size > MaxLeaseJournalBytes-2*MaxRequestJournalBytes {
		return ErrDisputed
	}
	return nil
}

// Host admits only one active lease and reserves its complete guest quota before
// launch. Retained histories from earlier leases count against the global bound.
func ReserveHostJournal(stateDir, lease string) error {
	root, err := LeaseDirectory(stateDir, lease)
	if err != nil {
		return err
	}
	parent := filepath.Dir(root)
	f, err := os.Open(parent)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	entries, err := f.Readdir(MaxHostJournalFiles + 1)
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) > MaxHostJournalFiles {
		return ErrDisputed
	}
	files := 0
	var size int64
	for _, entry := range entries {
		if !entry.IsDir() || !uuidPattern.MatchString(entry.Name()) {
			return ErrInvalid
		}
		if entry.Name() == lease {
			if _, _, err := journalUsage(filepath.Join(parent, entry.Name(), "journal"), MaxLeaseJournalFiles, MaxLeaseJournalBytes); err != nil {
				return err
			}
			continue
		}
		n, total, err := journalUsage(filepath.Join(parent, entry.Name(), "journal"), MaxHostJournalFiles, MaxHostJournalBytes)
		if err != nil {
			return err
		}
		files += n
		size += total
		if files > MaxHostJournalFiles-MaxLeaseJournalFiles || size > MaxHostJournalBytes-MaxLeaseJournalBytes {
			return ErrDisputed
		}
	}
	return nil
}
