package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/internal/update"
)

func TestSoftwareReconcilesRestartAndRetriesResult(t *testing.T) {
	running, err := update.FileSHA256("/proc/self/exe")
	if err != nil {
		t.Skip("Linux process executable required")
	}
	for _, scenario := range []string{"applied", "rolled-back", "expired", "changed", "cross-device", "busy", "retry-result"} {
		t.Run(scenario, func(t *testing.T) {
			state := softwareJournal{Started: true, Command: api.SoftwareCommand{RequestID: testJob, DeviceID: testDevice, Action: "update", ExpectedSHA256: strings.Repeat("a", 64), TargetSHA256: running, ExpiresAt: time.Now().Add(time.Hour)}}
			want := "applied"
			switch scenario {
			case "rolled-back":
				state.Command.TargetSHA256 = strings.Repeat("b", 64)
				want = "failed"
			case "expired":
				state.Started = false
				state.Command.ExpiresAt = time.Now().Add(-time.Hour)
				want = "failed"
			case "changed":
				state.Started = false
				state.Command.TargetSHA256 = strings.Repeat("b", 64)
				want = "failed"
			case "cross-device":
				state.Command.DeviceID = "another-device"
			}
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/hypermesh/agent/software/result" {
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(404)
					return
				}
				posts++
				var result api.SoftwareResult
				if json.NewDecoder(r.Body).Decode(&result) != nil || result.Outcome != want || result.RunningSHA256 != running {
					t.Errorf("unexpected result %+v", result)
				}
				if scenario == "retry-result" && posts == 1 {
					w.WriteHeader(503)
					return
				}
				w.Write([]byte(`{}`))
			}))
			defer server.Close()
			a := &Agent{cfg: Config{StateDir: t.TempDir()}, state: State{DeviceID: testDevice}, client: api.NewClient(server.URL, testTenant), log: discardLog(), hbOK: 1}
			a.client.DeviceSecret = testSecret
			path := filepath.Join(a.cfg.StateDir, "software-command.json")
			if err := saveSoftware(path, state); err != nil {
				t.Fatal(err)
			}
			if scenario == "busy" {
				a.pendingResult.Store(true)
			}
			_, err := a.reconcileSoftware(context.Background())
			if scenario == "cross-device" {
				if err == nil || posts != 0 {
					t.Fatal("cross-device command accepted")
				}
				return
			}
			if scenario == "busy" {
				if posts != 0 {
					t.Fatal("busy host acknowledged control")
				}
				return
			}
			if scenario == "retry-result" {
				if err == nil {
					t.Fatal("lost transport failure")
				}
				_, err = a.reconcileSoftware(context.Background())
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("acknowledged command journal remains")
			}
		})
	}
}
