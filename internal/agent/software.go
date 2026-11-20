package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/internal/update"
)

// softwareJournal is saved before replacement. The running process digest,
// confirmed startup and server acknowledgement are separate durable steps.
type softwareJournal struct {
	Binary  string              `json:"binary,omitempty"`
	Command api.SoftwareCommand `json:"command"`
	Started bool                `json:"started"`
	RetryAt time.Time           `json:"retry_at,omitempty"`
	Result  *api.SoftwareResult `json:"result,omitempty"`
}

func saveSoftware(path string, state softwareJournal) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".software-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// reconcileSoftware runs only in the serialized job loop. True keeps ordinary
// updating out while a control request or restart is unresolved.
func (a *Agent) reconcileSoftware(ctx context.Context) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, nil
	}
	a.maintenanceMu.Lock()
	defer a.maintenanceMu.Unlock()
	if a.Busy() {
		return false, nil
	}
	path := filepath.Join(a.cfg.StateDir, "software-command.json")
	var state softwareJournal
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) > 16384 || json.Unmarshal(raw, &state) != nil {
			return true, fmt.Errorf("invalid software command journal")
		}
	} else if !os.IsNotExist(err) {
		return true, err
	} else {
		command, err := a.client.PullSoftware(ctx, a.state.DeviceID)
		if err != nil {
			return false, err
		}
		if command == nil {
			return false, nil
		}
		state.Command = *command
	}
	if state.Binary == "" {
		state.Binary, err = a.softwareBinary()
		if err != nil {
			return true, err
		}
		if state.Started {
			marker, markerErr := update.ReadMarker(filepath.Join(a.cfg.StateDir, update.MarkerName))
			if markerErr != nil {
				return true, markerErr
			}
			if marker != nil {
				state.Binary = marker.Binary
			}
		}
	}
	if !filepath.IsAbs(state.Binary) || filepath.Clean(state.Binary) != state.Binary {
		return true, fmt.Errorf("software command requires an absolute installation path")
	}
	cmd := state.Command
	hashPattern := regexp.MustCompile(`^[a-f0-9]{64}$`)
	idPattern := regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	if cmd.DeviceID != a.state.DeviceID || !idPattern.MatchString(cmd.RequestID) || !hashPattern.MatchString(cmd.TargetSHA256) || !hashPattern.MatchString(cmd.ExpectedSHA256) || cmd.TargetSHA256 == cmd.ExpectedSHA256 || cmd.ExpiresAt.IsZero() || (cmd.Action != "update" && cmd.Action != "revert") {
		return true, fmt.Errorf("invalid software command")
	}
	running, err := update.FileSHA256("/proc/self/exe")
	if err != nil {
		return true, err
	}
	finish := func(outcome, reason string) error {
		state.Result = &api.SoftwareResult{DeviceID: cmd.DeviceID, RequestID: cmd.RequestID, Outcome: outcome, Reason: reason, RunningSHA256: running}
		return saveSoftware(path, state)
	}
	if state.Result == nil {
		if state.Started {
			marker, err := update.ReadMarker(filepath.Join(a.cfg.StateDir, update.MarkerName))
			if err != nil {
				return true, err
			}
			if marker != nil {
				// The original process has no startup watcher for a marker
				// created later. Recover an expired activation here; the target
				// process retains its own startup confirmation window.
				if running != cmd.ExpectedSHA256 || a.clock().Before(marker.Deadline) {
					return true, nil
				}
				if marker.Binary != state.Binary {
					return true, fmt.Errorf("software recovery marker names another binary")
				}
				if err := update.RollbackFile(marker.Binary, "/proc/self/exe"); err != nil {
					return true, fmt.Errorf("software marker recovery remains incomplete: %w", err)
				}
				if disk, err := update.FileSHA256(marker.Binary); err != nil || disk != running {
					return true, fmt.Errorf("software marker recovery verification failed")
				}
				if err := update.WriteBadBuild(filepath.Join(a.cfg.StateDir, update.BadName), marker.Build, marker.ReleaseID); err != nil {
					return true, err
				}
				if err := os.Remove(filepath.Join(a.cfg.StateDir, update.MarkerName)); err != nil {
					return true, err
				}
			}
			if a.heartbeatOK() == 0 {
				return true, nil
			}
			disk, hashErr := update.FileSHA256(state.Binary)
			if hashErr != nil || disk != running {
				if running != cmd.ExpectedSHA256 && running != cmd.TargetSHA256 {
					return true, fmt.Errorf("running software differs from both command binaries")
				}
				if err := update.RollbackFile(state.Binary, "/proc/self/exe"); err != nil {
					return true, fmt.Errorf("software restore remains incomplete: %w", err)
				}
				disk, hashErr = update.FileSHA256(state.Binary)
				if hashErr != nil || disk != running {
					return true, fmt.Errorf("software restore verification failed")
				}
			}
			if running == cmd.TargetSHA256 {
				err = finish("applied", "healthy")
			} else {
				err = finish("failed", "rolled-back")
			}
			if err != nil {
				return true, err
			}
		} else if !a.clock().Before(cmd.ExpiresAt) {
			if err := finish("failed", "expired"); err != nil {
				return true, err
			}
		} else if running != cmd.ExpectedSHA256 {
			if err := finish("failed", "installed-binary-changed"); err != nil {
				return true, err
			}
		} else {
			if a.clock().Before(state.RetryAt) {
				return true, nil
			}
			marker, markerErr := update.ReadMarker(filepath.Join(a.cfg.StateDir, update.MarkerName))
			if markerErr != nil {
				return true, markerErr
			}
			if marker != nil {
				return true, nil
			}
			if a.Busy() {
				return true, nil
			}
			state.Started = true
			if err := saveSoftware(path, state); err != nil {
				return true, err
			}
			operation, cancel := context.WithDeadline(ctx, cmd.ExpiresAt)
			err := a.selectedSelfUpdate(operation, false, cmd.TargetSHA256, cmd.Action == "revert", state.Binary)
			cancel()
			if errors.Is(err, errUpdateDeferred) {
				state.Started = false
				return true, saveSoftware(path, state)
			}
			if err != nil {
				// A failed restore leaves its marker for startup recovery. Do not
				// finalize that command until the running binary is known afterwards.
				marker, readErr := update.ReadMarker(filepath.Join(a.cfg.StateDir, update.MarkerName))
				if readErr != nil {
					return true, readErr
				}
				if marker != nil {
					return true, err
				}
				disk, hashErr := update.FileSHA256(state.Binary)
				if hashErr != nil || disk != running {
					return true, fmt.Errorf("software restore must finish before retry")
				}
				delay := 30 * time.Second
				var status *api.StatusError
				if errors.As(err, &status) && status != nil && status.HasRetryAfter && status.RetryAfter > delay {
					delay = status.RetryAfter
				}
				state.Started = false
				state.RetryAt = a.clock().Add(delay)
				return true, saveSoftware(path, state)
			} else {
				return true, nil
			}
		}
	}
	if err := a.client.PostSoftwareResult(ctx, *state.Result); err != nil {
		return true, err
	}
	return true, os.Remove(path)
}

func (a *Agent) softwareBinary() (string, error) {
	if a.installBinary != "" {
		return a.installBinary, nil
	}
	path := strings.TrimSpace(a.cfg.UpdateBinary)
	if path == "" {
		var err error
		path, err = os.Executable()
		if err != nil {
			return "", err
		}
	}
	return filepath.Abs(path)
}

// Completed result delivery may delay another software change, never workloads.
func (a *Agent) softwareBlocksWork() bool {
	raw, err := os.ReadFile(filepath.Join(a.cfg.StateDir, "software-command.json"))
	if os.IsNotExist(err) {
		return false
	}
	var state softwareJournal
	if err != nil || len(raw) > 16384 || json.Unmarshal(raw, &state) != nil {
		return true
	}
	return state.Started && state.Result == nil
}
