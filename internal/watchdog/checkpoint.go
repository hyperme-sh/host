package watchdog

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const checkpointName = "recovery-watchdog.json"
const maxCheckpointSize = 4096

// Checkpoint stores the retry budget in the installer-owned state directory.
// Its caller must hold the profile lock while reading or writing a checkpoint.
type Checkpoint struct {
	Dir string
}

func (c Checkpoint) Load() (State, error) {
	var state State
	path := filepath.Join(c.Dir, checkpointName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxCheckpointSize {
		return state, errors.New("unsafe watchdog checkpoint")
	}
	file, err := os.Open(path)
	if err != nil {
		return state, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return state, errors.New("watchdog checkpoint changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCheckpointSize+1))
	if err != nil {
		return state, err
	}
	if len(data) > maxCheckpointSize {
		return state, errors.New("watchdog checkpoint too large")
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	return state, nil
}

func (c Checkpoint) Save(state State) error {
	file, err := os.CreateTemp(c.Dir, ".recovery-watchdog-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := json.NewEncoder(file).Encode(state); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(c.Dir, checkpointName)); err != nil {
		return err
	}
	dir, err := os.Open(c.Dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
