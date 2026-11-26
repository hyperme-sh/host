package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/internal/buildinfo"
	"github.com/FyberLabs/hypermesh-host/internal/update"
)

// The updater sees Busy and nothing else from the agent loop.
var _ update.IdleGate = (*Agent)(nil)

// Busy is true when a restart would drop a lease or an unacked job.
// The job loop calls it at the start of a check and again before
// install and restart. Heartbeat does not call it.
func (a *Agent) Busy() bool {
	if a.maintenanceHeld() {
		return true
	}
	h := a.currentLease()
	if h != nil && strings.TrimSpace(h.LeaseID) != "" {
		return true
	}
	return a.pendingResult.Load()
}

func (a *Agent) heartbeatOK() uint64 {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	return a.hbOK
}

func (a *Agent) startUpdateWatch(ctx context.Context) {
	if strings.TrimSpace(a.cfg.UpdateChannel) == "" {
		return
	}
	if a.updateWatch != nil {
		a.updateWatch(ctx)
		return
	}
	marker, err := filepath.Abs(filepath.Join(a.cfg.StateDir, update.MarkerName))
	if err != nil {
		a.log.Warn("update watch", "err", err)
		return
	}
	baseline := a.heartbeatOK()
	go update.Watch(ctx, update.WatchConfig{
		MarkerPath:  marker,
		Interval:    time.Second,
		HeartbeatOK: a.heartbeatOK,
		Baseline:    baseline,
		Rollback: func() error {
			m, err := update.ReadMarker(marker)
			if err != nil || m == nil {
				if err == nil {
					return nil
				}
				return err
			}
			return update.RollbackFile(m.Binary, m.Backup)
		},
		Exit: os.Exit,
		Log: func(msg string, args ...any) {
			a.log.Warn(msg, args...)
		},
		Logger:       a.log,
		RunningBuild: buildinfo.CurrentBuild(),
	})
}

var errUpdateDeferred = errors.New("update deferred while busy")

func (a *Agent) maybeSelfUpdate(ctx context.Context) {
	a.maintenanceMu.Lock()
	defer a.maintenanceMu.Unlock()
	if a.Busy() {
		return
	}
	if strings.TrimSpace(a.cfg.UpdateChannel) == "" {
		return
	}
	every := a.cfg.UpdateEvery
	if every <= 0 {
		every = time.Hour
	}
	now := a.clock()
	if !a.nextUpdateRetry.IsZero() {
		if now.Before(a.nextUpdateRetry) {
			return
		}
	} else if !a.lastUpdateCheck.IsZero() && now.Sub(a.lastUpdateCheck) < every {
		return
	}
	fn := a.selfUpdate
	if fn == nil {
		fn = a.defaultSelfUpdate
	}
	err := fn(ctx, false)
	now = a.clock()
	if errors.Is(err, errUpdateDeferred) {
		// A lease or result became pending during verification. The next idle
		// job tick should retry instead of consuming the hourly interval.
		a.nextUpdateRetry = now
		return
	}
	if err != nil {
		a.updateFailures++
		delay := 15 * time.Second
		for n := 1; n < a.updateFailures && delay < 5*time.Minute; n++ {
			delay *= 2
		}
		if delay > 5*time.Minute {
			delay = 5 * time.Minute
		}
		var status *api.StatusError
		if errors.As(err, &status) && status != nil && status.HasRetryAfter && status.RetryAfter > delay {
			delay = status.RetryAfter
		}
		a.nextUpdateRetry = now.Add(delay)
		a.log.Warn("update check failed", "err", update.RedactQuery(err.Error()), "retry_after", delay)
		return
	}
	a.lastUpdateCheck = now
	a.nextUpdateRetry = time.Time{}
	a.updateFailures = 0
}

func (a *Agent) defaultSelfUpdate(ctx context.Context, busy bool) error {
	return a.selectedSelfUpdate(ctx, busy, "", false, "")
}

func (a *Agent) selectedSelfUpdate(ctx context.Context, busy bool, target string, revert bool, binary string) error {
	var err error
	if binary == "" {
		binary, err = a.softwareBinary()
		if err != nil {
			return err
		}
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return err
	}
	marker, err := filepath.Abs(filepath.Join(a.cfg.StateDir, update.MarkerName))
	if err != nil {
		return err
	}
	badBuild, err := update.ReadBadBuild(filepath.Join(filepath.Dir(marker), update.BadName))
	if err != nil {
		return err
	}
	cfg := update.Config{
		TargetSHA256:   target,
		Channel:        a.cfg.UpdateChannel,
		CurrentChannel: buildinfo.CurrentChannel(),
		CurrentVersion: buildinfo.CurrentVersion(),
		CurrentCommit:  buildinfo.Current(),
		CurrentBuild:   buildinfo.CurrentBuild(),
		BadBuild:       badBuild,
		Arch:           runtime.GOARCH,
		BinaryPath:     binary,
		PubKeyPath:     a.cfg.UpdatePubKey,
		Fingerprints:   a.cfg.UpdateFingerprints,
		MarkerPath:     marker,
		Busy:           busy,
		RollbackWindow: a.cfg.UpdateRollback,
	}
	hooks := update.Hooks{
		Source:    a.updateSource(),
		StillBusy: a.Busy,
		Restart: func(ctx context.Context) error {
			return update.RestartInstalledAgent(ctx, binary, filepath.Dir(marker))
		},
		Log:       a.log,
	}
	var plan update.Plan
	if revert {
		plan, err = update.Revert(ctx, cfg, target, hooks)
	} else {
		plan, err = update.Tick(ctx, cfg, hooks)
	}
	if err != nil {
		return err
	}
	logUpdate(a.log, plan)
	if target != "" && plan.Action != update.ActionInstall && plan.Action != update.ActionDefer {
		return fmt.Errorf("requested software target unavailable")
	}
	if plan.Action == update.ActionDefer {
		return errUpdateDeferred
	}
	return nil
}

// logUpdate writes one update decision. The steady state, already
// running the signed build, is debug. Install, reject, and defer stay
// at info.
func logUpdate(log *slog.Logger, plan update.Plan) {
	args := []any{
		"action", plan.Action,
		"version", plan.Version,
		"commit", plan.Commit,
		"reason", update.RedactQuery(plan.Reason),
	}
	if plan.Action == update.ActionSkip && plan.Reason == "up to date" {
		log.Debug("update", args...)
		return
	}
	log.Info("update", args...)
}

// updateSource asks the control plane with the device credential the
// agent already uses. Artifact bytes are fetched from the SAS URL
// with no Authorization header.
func (a *Agent) updateSource() update.Source {
	return update.Source{
		LatestFn: func(ctx context.Context, channel string) (*update.Candidate, error) {
			m, err := a.client.LatestUpdate(ctx, channel, a.state.DeviceID)
			if err != nil || m == nil {
				return nil, err
			}
			return candidateFromManifest(m), nil
		},
	}
}

func candidateFromManifest(m *api.UpdateManifest) *update.Candidate {
	c := &update.Candidate{
		Channel:   m.Channel,
		Version:   m.Version,
		Commit:    m.Commit,
		ReleaseID: m.ReleaseID,
		Build:     m.Build,
	}
	for _, art := range m.Artifacts {
		c.Artifacts = append(c.Artifacts, update.Artifact{
			Name:   art.Name,
			SHA256: art.SHA256,
			Size:   art.Size,
			URL:    art.URL,
		})
	}
	return c
}
