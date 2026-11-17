package runtime

import "context"

// ContainerCapture owns optional native cleanup outside the workload. A nil
// implementation preserves the existing no-capture launch path.
type ContainerCapture interface {
	Start(context.Context, func(context.Context, ...string) ([]byte, error), []string) ([]byte, error)
	Finish(context.Context, string, bool) error
}
