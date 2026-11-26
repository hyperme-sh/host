package watchdog

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fixture struct {
	health   Health
	state    State
	saveErr  error
	restarts int
	repairs  int
}

func (f *fixture) Inspect(context.Context) (Health, error) { return f.health, nil }
func (f *fixture) Save(s State) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.state = s
	return nil
}
func (f *fixture) Restart(context.Context) error { f.restarts++; return nil }
func (f *fixture) Repair(context.Context) error  { f.repairs++; return nil }

func TestRecoveryDefersWithoutChangingInstallation(t *testing.T) {
	for _, health := range []Health{
		{IdentityPresent: true},
		{IdentityPresent: true, OwnershipKnownIdle: true, RebootRequired: true},
		{IdentityPresent: true, OwnershipKnownIdle: true, OwnerPaused: true},
		{IdentityPresent: true, OwnershipKnownIdle: true, Running: true},
		{OwnershipKnownIdle: true},
	} {
		f := &fixture{health: health}
		result, err := Check(context.Background(), f, State{}, time.Now())
		if err != nil || (result != Deferred && result != IdentityMissing) ||
			f.restarts != 0 || f.repairs != 0 || f.state.Attempts != 0 {
			t.Fatalf("unsafe action for %+v: %s, %v", health, result, err)
		}
	}
}

func TestRecoveryBudgetSurvivesInterruptedAttempt(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	f := &fixture{health: Health{IdentityPresent: true, OwnershipKnownIdle: true, BinaryVerified: true}}
	if result, err := Check(ctx, f, f.state, now); err != nil || result != RepairAttempted || f.restarts != 1 || f.state.Attempts != 1 {
		t.Fatalf("first attempt: %s, %v, %+v", result, err, f)
	}
	if result, err := Check(ctx, f, f.state, now); err != nil || result != Deferred || f.repairs != 0 {
		t.Fatalf("retry during backoff: %s, %v", result, err)
	}
	for f.state.Attempts < MaxAttempts {
		if result, err := Check(ctx, f, f.state, f.state.NextAttempt); err != nil || result != RepairAttempted {
			t.Fatalf("retry: %s, %v", result, err)
		}
	}
	if result, err := Check(ctx, f, f.state, f.state.NextAttempt); err != nil || result != RetryExhausted || f.repairs != MaxAttempts-1 {
		t.Fatalf("budget: %s, %v, %+v", result, err, f)
	}
	f.health.Running = true
	if result, err := Check(ctx, f, f.state, f.state.NextAttempt); err != nil || result != Healthy || f.state != (State{}) {
		t.Fatalf("recovery readback: %s, %v, %+v", result, err, f)
	}
}

func TestRecoveryRequiresDurableCheckpoint(t *testing.T) {
	f := &fixture{health: Health{IdentityPresent: true, OwnershipKnownIdle: true}, saveErr: errors.New("disk full")}
	if result, err := Check(context.Background(), f, State{}, time.Now()); err == nil ||
		result != Deferred || f.repairs != 0 {
		t.Fatalf("repair without checkpoint: %s, %v, %+v", result, err, f)
	}
}
