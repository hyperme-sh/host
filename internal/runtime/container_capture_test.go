package runtime

import (
	"context"
	"errors"
	"testing"
)

type captureContract struct {
	started, finished bool
	stopped           bool
}

func (c *captureContract) Start(ctx context.Context, run func(context.Context, ...string) ([]byte, error), args []string) ([]byte, error) {
	c.started = true
	return run(ctx, args...)
}
func (c *captureContract) Finish(_ context.Context, _ string, stopped bool) error {
	c.finished = true
	c.stopped = stopped
	return nil
}
func TestContainerStopRevokesCaptureEvenWhenDockerFails(t *testing.T) {
	for _, kind := range []string{"cpu", "nvidia", "rocm"} {
		t.Run(kind, func(t *testing.T) {
			capture := &captureContract{}
			run := func(_ context.Context, _ string, args ...string) ([]byte, error) {
				return nil, errors.New("stop failed")
			}
			var starter Starter
			if kind == "rocm" {
				starter = &HIP{Capture: capture, Run: run}
			} else {
				starter = &NVIDIA{Capture: capture, Run: run, cpu: kind == "cpu"}
			}
			if err := starter.Stop(context.Background(), &Handle{ContainerID: "worker"}); err == nil {
				t.Fatal("lost Docker failure")
			}
			if !capture.finished || capture.stopped {
				t.Fatal("failed stop did not revoke capture")
			}
		})
	}
}
