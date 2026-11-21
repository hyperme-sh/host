package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/internal/pathb"
)

func (a *Agent) sustainedPath(job api.Job) string {
	sum := sha256.Sum256([]byte(job.JobID))
	return filepath.Join(a.cfg.StateDir, fmt.Sprintf("cert-result-%x.json", sum))
}
func (a *Agent) retrySustained(ctx context.Context, job api.Job) (bool, error) {
	raw, err := os.ReadFile(a.sustainedPath(job))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	var body api.SustainedResult
	if len(raw) > 65536 || json.Unmarshal(raw, &body) != nil || body.JobID != job.JobID || body.DeviceID != a.state.DeviceID || body.EnvironmentHash != job.EnvironmentHash || body.MeasurementProtocol != pathb.SustainedDecodeProtocol {
		return true, fmt.Errorf("saved certification result does not match assignment")
	}
	if err := a.client.PostSustainedResult(ctx, body); err != nil {
		return true, err
	}
	return true, os.Remove(a.sustainedPath(job))
}
func (a *Agent) postSustained(ctx context.Context, job api.Job, result pathb.Result) error {
	if !result.Passed && result.EnvironmentHash == "" {
		result.EnvironmentHash = job.EnvironmentHash
	}
	body := api.SustainedResult{DeviceID: a.state.DeviceID, JobID: job.JobID,
		EnvironmentHash: result.EnvironmentHash, MeasurementProtocol: pathb.SustainedDecodeProtocol,
		Passed: result.Passed, FileHash: result.MeasuredGGUFHash, ThermalC: result.ThermalC}
	if result.Measurement != nil {
		raw, err := json.Marshal(result.Measurement)
		if err != nil {
			return err
		}
		body.Measurement = raw
	}
	if err := writeJSON0600(a.sustainedPath(job), body); err != nil {
		return err
	}
	_, err := a.retrySustained(ctx, job)
	return err
}
