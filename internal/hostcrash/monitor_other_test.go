//go:build !linux && !darwin

package hostcrash

import (
	"errors"
	"testing"
	"time"
)

func TestUnsupportedMonitorNeverAdvertisesOrReports(t *testing.T) {
	if MonitorSupported() {
		t.Fatal("unsupported build advertised Go supervision")
	}
	child, err := BindChild()
	if child || err != nil {
		t.Fatal("unsupported build attempted to bind a runtime pipe")
	}
	called := false
	_, err = Monitor(func(time.Time) { called = true })
	if !errors.Is(err, ErrUnavailable) || called {
		t.Fatal("unsupported monitor must refuse without reporting")
	}
}
