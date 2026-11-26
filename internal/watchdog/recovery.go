// Package watchdog contains the shared policy for local Host agent repair.
package watchdog

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	MaxAttempts = 4
	RetryDelay  = 15 * time.Minute
)

// State must live outside the agent executable and persist across process exits.
type State struct {
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"next_attempt"`
}

type Health struct {
	Running            bool
	BinaryVerified     bool
	IdentityPresent    bool
	OwnershipKnownIdle bool
	RebootRequired     bool
	OwnerPaused        bool
}

type Result string

const (
	Healthy         Result = "healthy"
	Deferred        Result = "deferred"
	IdentityMissing Result = "identity_missing"
	RetryExhausted  Result = "retry_exhausted"
	RepairAttempted Result = "repair_attempted"
)

// Operations are supplied by a single installer-owned profile. Save must commit
// atomically. Callers hold the profile's shared update lock through this call.
// Repair must verify a same-channel artifact before replacing the executable
// and recheck workload ownership before mutation.
type Operations interface {
	Inspect(context.Context) (Health, error)
	Save(State) error
	Restart(context.Context) error
	Repair(context.Context) error
}

func Check(ctx context.Context, ops Operations, state State, now time.Time) (Result, error) {
	if state.Attempts < 0 || state.Attempts > MaxAttempts ||
		(state.Attempts == 0) != state.NextAttempt.IsZero() {
		return Deferred, errors.New("invalid watchdog checkpoint")
	}
	health, err := ops.Inspect(ctx)
	if err != nil {
		return Deferred, err
	}
	if !health.IdentityPresent {
		return IdentityMissing, nil
	}
	if health.Running && health.BinaryVerified {
		if state.Attempts != 0 {
			if err := ops.Save(State{}); err != nil {
				return Deferred, err
			}
		}
		return Healthy, nil
	}
	if health.Running || health.RebootRequired || health.OwnerPaused || !health.OwnershipKnownIdle {
		return Deferred, nil
	}
	if state.Attempts == MaxAttempts {
		return RetryExhausted, nil
	}
	if now.Before(state.NextAttempt) {
		return Deferred, nil
	}

	oldAttempts := state.Attempts
	state.Attempts++
	state.NextAttempt = now.Add(RetryDelay)
	if err := ops.Save(state); err != nil {
		return Deferred, fmt.Errorf("save watchdog checkpoint before repair: %w", err)
	}

	if oldAttempts == 0 && health.BinaryVerified {
		return RepairAttempted, ops.Restart(ctx)
	}
	return RepairAttempted, ops.Repair(ctx)
}
