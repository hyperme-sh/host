//go:build linux || darwin

package installer

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestWatchdogServiceContracts(t *testing.T) {
	if !strings.Contains(watchdogSystemdService, "ConditionPathExists=/var/lib/hypermesh/activation-approved") ||
		!strings.Contains(watchdogSystemdService, "ExecStart="+watchdogExecutable+" recovery-watchdog") ||
		!strings.Contains(watchdogSystemdTimer, "OnUnitInactiveSec=5min") {
		t.Fatal("incorrect systemd recovery wiring")
	}
	parser := xml.NewDecoder(strings.NewReader(watchdogLaunchDaemon))
	for {
		if _, err := parser.Token(); err != nil {
			if err != io.EOF {
				t.Fatal(err)
			}
			break
		}
	}
	if !strings.Contains(watchdogLaunchDaemon, "<string>"+watchdogExecutable+"</string>") ||
		!strings.Contains(watchdogLaunchDaemon, "<key>StartInterval</key><integer>300</integer>") {
		t.Fatal("incorrect launchd recovery wiring")
	}
}

func TestWatchdogServiceStateRequiresKnownStoppedProfile(t *testing.T) {
	for _, test := range []struct {
		state         string
		pid           string
		sub           string
		running, down bool
	}{
		{"active", "11", "running", true, false},
		{"failed", "0", "failed", false, true},
		{"inactive", "0", "dead", false, false},
		{"activating", "0", "start", false, false},
		{"activating", "0", "auto-restart", false, true},
		{"deactivating", "11", "stop", false, false},
	} {
		running, down, err := systemdRecoveryState([]string{"ActiveState=" + test.state, "LoadState=loaded", "MainPID=" + test.pid, "SubState=" + test.sub})
		if err != nil || running != test.running || down != test.down {
			t.Fatalf("systemd state %+v: %v %v %v", test, running, down, err)
		}
	}
	if _, down, err := systemdRecoveryState([]string{"ActiveState=failed", "LoadState=loaded", "MainPID=unknown", "SubState=failed"}); err == nil || down {
		t.Fatal("unknown PID treated as stopped")
	}
	identity := "\tprogram = " + watchdogAgent + "\n"
	for _, test := range []struct {
		state         string
		running, down bool
	}{
		{"\tstate = running\n\tpid = 42\n", true, false},
		{"\tstate = spawn scheduled\n", false, true},
		{"\tstate = waiting\n", false, false},
		{"\tstate = spawn scheduled\n\tpid = 42\n", false, false},
	} {
		running, down, err := launchdRecoveryState(identity + test.state)
		if err != nil || running != test.running || down != test.down {
			t.Fatalf("launchd state %+v: %v %v %v", test, running, down, err)
		}
	}
	if _, down, err := launchdRecoveryState("\tstate = spawn scheduled\n"); err == nil || down {
		t.Fatal("unknown launchd executable treated as stopped")
	}
}
