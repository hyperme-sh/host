package pathb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"time"
)

const SustainedDecodeProtocol = "sustained-decode-v2"
const sustainedDecodeTokens = 64

// DecodeMeasurement keeps server decode time separate from full-window warmup.
// The containing job binds the model and the actual runtime image.
type DecodeMeasurement struct {
	ImageDigest            string `json:"image_digest"`
	DecodeTokens           int    `json:"decode_tokens"`
	DecodeElapsedMS        int64  `json:"decode_elapsed_ms"`
	ContextPromptTokens    int    `json:"context_prompt_tokens"`
	ContextGeneratedTokens int    `json:"context_generated_tokens"`
	ContextElapsedMS       int64  `json:"context_elapsed_ms"`
}

// MeasureSustained first verifies the full context, then times 64 deterministic
// generated tokens using llama.cpp decode timing, excluding HTTP and prefill.
func (r Runner) MeasureSustained(ctx context.Context, tokens int) (*ContextFit, *DecodeMeasurement, error) {
	fit, err := r.CheckContextFit(ctx, tokens)
	if err != nil {
		return nil, nil, err
	}
	base, err := url.Parse(r.endpoint())
	if err != nil {
		return nil, nil, err
	}
	base.Path = "/completion"
	base.RawPath = ""
	body, _ := json.Marshal(map[string]any{
		"model": r.Model, "prompt": "Continue the sequence of integers: 1, 2, 3, 4, 5,",
		"n_predict": sustainedDecodeTokens, "stream": false, "cache_prompt": false,
		"ignore_eos": true, "temperature": 0, "seed": 0, "stop": []string{}, "id_slot": 0,
	})
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := *r.client()
	client.Timeout = 2 * time.Minute
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("sustained decode transport failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 || response.StatusCode != 200 {
		return nil, nil, fmt.Errorf("sustained decode response unavailable")
	}
	var out struct {
		Predicted int    `json:"tokens_predicted"`
		Stop      bool   `json:"stop"`
		StopType  string `json:"stop_type"`
		Timings   struct {
			Tokens       int     `json:"predicted_n"`
			Milliseconds float64 `json:"predicted_ms"`
		} `json:"timings"`
	}
	if json.Unmarshal(raw, &out) != nil || out.Predicted != sustainedDecodeTokens || out.Timings.Tokens != sustainedDecodeTokens || !out.Stop || out.StopType != "limit" || math.IsNaN(out.Timings.Milliseconds) || math.IsInf(out.Timings.Milliseconds, 0) || out.Timings.Milliseconds <= 0 || out.Timings.Milliseconds > 120000 {
		return nil, nil, fmt.Errorf("sustained decode requires complete counts and finite decode timing")
	}
	measured := &DecodeMeasurement{DecodeTokens: out.Timings.Tokens, DecodeElapsedMS: int64(math.Ceil(out.Timings.Milliseconds)), ContextPromptTokens: fit.PromptTokens, ContextGeneratedTokens: fit.GeneratedTokens, ContextElapsedMS: fit.ElapsedMS}
	return fit, measured, nil
}
