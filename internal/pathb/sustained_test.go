package pathb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSustainedDecodeSeparatesWarmupHTTPAndGeneration(t *testing.T) {
	for _, scenario := range []string{"valid", "series", "partial-series", "short", "missing-timing", "zero-time", "too-long", "eos", "count-mismatch", "warmup-failed"} {
		t.Run(scenario, func(t *testing.T) {
			var decodeCalls atomic.Int32
			protocol := SustainedDecodeProtocol
			if scenario == "series" || scenario == "partial-series" {
				protocol = SustainedSeriesProtocol
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/props":
					w.Write([]byte(`{"default_generation_settings":{"n_ctx":512},"total_slots":1}`))
					return
				case "/tokenize":
					w.Write([]byte(`{"tokens":[123,456]}`))
					return
				case "/completion":
					var req map[string]any
					if json.NewDecoder(r.Body).Decode(&req) != nil {
						t.Fatal("invalid request")
					}
					if req["n_predict"] == float64(16) {
						if scenario == "warmup-failed" {
							w.WriteHeader(503)
							return
						}
						time.Sleep(2 * time.Millisecond)
						w.Write([]byte(`{"tokens_evaluated":496,"tokens_predicted":16,"truncated":false,"stop":true,"stop_type":"limit","generation_settings":{"n_ctx":512}}`))
						return
					}
					if req["n_predict"] != float64(64) || req["cache_prompt"] != false || req["ignore_eos"] != true || req["temperature"] != float64(0) || req["seed"] != float64(0) {
						t.Error("non-deterministic decode request")
					}
					calls := decodeCalls.Add(1)
					if scenario == "partial-series" && calls == 3 {
						w.WriteHeader(503)
						return
					}
					timings := map[string]any{"predicted_n": 64, "predicted_ms": 1000.25 + float64(calls-1)*1000}
					response := map[string]any{"tokens_predicted": 64, "stop": true, "stop_type": "limit", "timings": timings}
					switch scenario {
					case "short":
						response["tokens_predicted"] = 3
						timings["predicted_n"] = 3
					case "missing-timing":
						delete(response, "timings")
					case "zero-time":
						timings["predicted_ms"] = 0
					case "too-long":
						timings["predicted_ms"] = 120001
					case "eos":
						response["stop_type"] = "eos"
					case "count-mismatch":
						timings["predicted_n"] = 63
					}
					// A separate HTTP delay must not become the decode denominator.
					time.Sleep(10 * time.Millisecond)
					json.NewEncoder(w).Encode(response)
				default:
					t.Error("unexpected endpoint")
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			runner := Runner{Model: "pinned-model", Endpoint: server.URL}
			fit, measurement, err := runner.MeasureSustained(context.Background(), 512, protocol)
			if scenario != "valid" && scenario != "series" {
				if err == nil || measurement != nil {
					t.Fatal("incomplete measurement accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "series" {
				if !fit.ValidFor(512) || decodeCalls.Load() != 4 || measurement.Warmup == nil ||
					measurement.Warmup.DecodeElapsedMS != 1001 || len(measurement.Samples) != 3 ||
					measurement.DecodeTokens != 0 || measurement.DecodeElapsedMS != 0 {
					t.Fatalf("wrong series %+v", measurement)
				}
				for index, sample := range measurement.Samples {
					if sample.DecodeTokens != 64 || sample.DecodeElapsedMS != int64(2001+index*1000) {
						t.Fatalf("wrong sample %+v", sample)
					}
				}
				return
			}
			if decodeCalls.Load() != 1 || !fit.ValidFor(512) || measurement.DecodeTokens != 64 || measurement.DecodeElapsedMS != 1001 || measurement.ContextElapsedMS != fit.ElapsedMS {
				t.Fatalf("wrong measurement %+v", measurement)
			}
		})
	}
}
