package agent

import (
	"runtime"
	"testing"

	"github.com/FyberLabs/hypermesh-host/terms"
)

func TestCrashReporterPlatformAdmission(t *testing.T) {
	cfg := Config{StateDir: t.TempDir()}
	writeTermsState(t, cfg.StateDir, State{
		DeviceID: "dev-1", DeviceSecret: "secret-1", TermsVersion: terms.Version,
		TermsSHA256: terms.SHA256(), AcceptedAt: "2026-11-05T00:00:00Z",
	})
	if !EnrollmentTermsCurrent(cfg.StateDir) {
		t.Fatal("fixture must have current accepted enrollment")
	}
	t.Setenv("HYPERMESH_HOST_CRASH_ENABLED", "1")
	t.Setenv("HYPERMESH_HOST_CRASH_REGISTRATION_URL", "https://crash.example/api/crash/register")
	for _, valid := range []bool{true, false} {
		dsn := "https://0123456789abcdef0123456789abcdef@crash.example/1"
		if !valid {
			dsn = "not-a-dsn"
		}
		t.Setenv("HYPERMESH_HOST_CRASH_DSN", dsn)
		reporter, err := CrashReporter(cfg)
		if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
			if valid != (reporter != nil) || valid != (err == nil) {
				t.Fatal("supported platform lost destination validation")
			}
		} else if reporter != nil || err != nil {
			t.Fatal("unsupported Go monitor must not enter agent startup failure path")
		}
		// The shared native sender remains independently usable and validates
		// configuration even when this platform lacks Go process supervision.
		sender, err := crashSender(cfg)
		if valid != (sender != nil) || valid != (err == nil) {
			t.Fatal("Go capability changed shared native sender behavior")
		}
	}
}

func TestCrashReportingDisabledAndUnaccepted(t *testing.T) {
	t.Setenv("HYPERMESH_HOST_CRASH_DSN", "not-a-dsn")
	cfg := Config{StateDir: t.TempDir()}
	for _, enabled := range []string{"", "0", "true", "1"} {
		t.Setenv("HYPERMESH_HOST_CRASH_ENABLED", enabled)
		reporter, err := CrashReporter(cfg)
		if reporter != nil || err != nil {
			t.Fatalf("unaccepted or disabled configuration admitted: %q", enabled)
		}
	}
}

func TestNativeCrashDoesNotAttachWithoutCurrentTerms(t *testing.T) {
	t.Setenv("HYPERMESH_HOST_NATIVE_CRASH_ENABLED", "1")
	t.Setenv("HYPERMESH_HOST_CRASH_ENABLED", "1")
	metal := nativeMetal(Config{StateDir: t.TempDir()})
	if metal.Run != nil {
		t.Fatal("native adapter attached before accepted enrollment")
	}
}
