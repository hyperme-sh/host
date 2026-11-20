package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/internal/pathb"
)

func TestSustainedReportPersistsExactSampleUntilAcknowledged(t *testing.T) {
	var first []byte
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != api.Prefix+"/agent/certification/sustained-result" {
			t.Errorf("wrong endpoint %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		posts++
		if posts == 1 {
			first = raw
			w.WriteHeader(503)
			return
		}
		if !bytes.Equal(first, raw) {
			t.Error("retry changed original measurement")
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	a := &Agent{cfg: Config{StateDir: t.TempDir()}, state: State{DeviceID: testDevice}, client: api.NewClient(server.URL, testTenant)}
	a.client.DeviceSecret = testSecret
	job := api.Job{JobID: testJob, EnvironmentHash: "sha256:" + strings.Repeat("a", 64), MeasurementProtocol: pathb.SustainedDecodeProtocol}
	result := pathb.Result{Passed: true, EnvironmentHash: job.EnvironmentHash, MeasuredGGUFHash: "sha256:" + strings.Repeat("b", 64), Measurement: &pathb.DecodeMeasurement{DecodeTokens: 64, DecodeElapsedMS: 6400}}
	if err := a.postSustained(context.Background(), job, result); err == nil {
		t.Fatal("lost upload failure")
	}
	info, err := os.Stat(a.sustainedPath(job))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("report not durably private", err)
	}
	changed := job
	changed.EnvironmentHash = "sha256:" + strings.Repeat("c", 64)
	if found, err := a.retrySustained(context.Background(), changed); !found || err == nil || posts != 1 {
		t.Fatal("cross-environment replay accepted")
	}
	if found, err := a.retrySustained(context.Background(), job); !found || err != nil {
		t.Fatal(found, err)
	}
	if _, err := os.Stat(a.sustainedPath(job)); !os.IsNotExist(err) {
		t.Fatal("acknowledged report retained")
	}
}

func TestSustainedAssignedWorkloadUsesPinsAndCleans(t *testing.T) {
	a, job, calls := certFixture(t, 200)
	job.SuiteID, job.MeasurementProtocol = pathb.SustainedDecodeProtocol, pathb.SustainedDecodeProtocol
	job.CertificationContextTokens = 512
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/props":
			w.Write([]byte(`{"default_generation_settings":{"n_ctx":512},"total_slots":1}`))
		case "/tokenize":
			w.Write([]byte(`{"tokens":[123]}`))
		case "/completion":
			var req map[string]any
			json.NewDecoder(r.Body).Decode(&req)
			if req["n_predict"] == float64(16) {
				time.Sleep(2 * time.Millisecond)
				w.Write([]byte(`{"tokens_evaluated":496,"tokens_predicted":16,"truncated":false,"stop":true,"stop_type":"limit","generation_settings":{"n_ctx":512}}`))
			} else {
				w.Write([]byte(`{"tokens_predicted":64,"stop":true,"stop_type":"limit","timings":{"predicted_n":64,"predicted_ms":6400}}`))
			}
		default:
			w.Write([]byte(`{"choices":[{"message":{"content":"ready"}}],"usage":{"completion_tokens":1}}`))
		}
	}))
	defer server.Close()
	a.certEndpoint = server.URL
	got := a.runJob(context.Background(), job)
	if !got.Passed || !got.WorkloadVerified || got.Measurement == nil || got.DecodeTokS != 10 || got.MeasuredGGUFHash != job.FileHash {
		t.Fatalf("%+v", got)
	}
	if got.Measurement.ImageDigest != job.ImageDigest || got.Measurement.ContextPromptTokens != 496 {
		t.Fatal("pins or context lost")
	}
	var joined string
	for _, args := range *calls {
		joined += strings.Join(args, " ") + "\n"
	}
	for _, required := range []string{"pull " + job.ImageDigest, "LLAMA_ARG_CTX_SIZE=512", "LLAMA_ARG_N_PARALLEL=1", "stop cert-container", "rm hypermesh-cert-bench-"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing %s in %s", required, joined)
		}
	}
}
