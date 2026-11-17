package agent

import "testing"

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
