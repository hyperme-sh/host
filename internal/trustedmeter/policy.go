// Package trustedmeter implements the count-only Plane meter protocol.
// It is not an attester and cannot turn an ordinary host into a trusted runtime.
package trustedmeter

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
)

const Policy = "processed-input-accepted-output-v1"

var PolicySHA256 = func() string { h := sha256.Sum256([]byte(Policy)); return hex.EncodeToString(h[:]) }()
var ErrInvalid = errors.New("invalid trusted meter record")
var ErrDisputed = errors.New("trusted execution remains disputed")

// HiddenOutput is a subset of AcceptedOutput. Cached input is not processed input.
type Counters struct {
	ProcessedInput      int64 `json:"processed_input"`
	AcceptedOutput      int64 `json:"accepted_output"`
	HiddenOutput        int64 `json:"hidden_output"`
	CacheHits           int64 `json:"cache_hits"`
	RejectedSpeculative int64 `json:"rejected_speculative"`
}

func (c Counters) Billable() (int64, error) {
	if c.ProcessedInput < 0 || c.AcceptedOutput < 0 || c.HiddenOutput < 0 || c.CacheHits < 0 || c.RejectedSpeculative < 0 || c.HiddenOutput > c.AcceptedOutput || c.ProcessedInput > math.MaxInt64-c.AcceptedOutput {
		return 0, ErrInvalid
	}
	return c.ProcessedInput + c.AcceptedOutput, nil
}
func (c Counters) Add(d Counters) (Counters, error) {
	if _, err := d.Billable(); err != nil {
		return c, err
	}
	a := []int64{c.ProcessedInput, c.AcceptedOutput, c.HiddenOutput, c.CacheHits, c.RejectedSpeculative}
	b := []int64{d.ProcessedInput, d.AcceptedOutput, d.HiddenOutput, d.CacheHits, d.RejectedSpeculative}
	for i := range a {
		if a[i] < 0 || a[i] > math.MaxInt64-b[i] {
			return c, ErrInvalid
		}
		a[i] += b[i]
	}
	n := Counters{a[0], a[1], a[2], a[3], a[4]}
	_, err := n.Billable()
	return n, err
}
