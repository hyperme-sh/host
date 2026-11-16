package trustedmeter

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"time"
)

type OwnerRecord struct {
	Kind          string          `json:"kind"`
	Operation     string          `json:"operation"`
	TenantID      string          `json:"tenant_id"`
	LeaseID       string          `json:"lease_id"`
	GatewayID     string          `json:"gateway_id"`
	RequestSHA256 string          `json:"request_sha256"`
	Result        json.RawMessage `json:"result"`
}
type Grant struct {
	StartID       string `json:"start_id"`
	IssuedAt      *int64 `json:"issued_at"`
	Deadline      int64  `json:"deadline"`
	MaxBillable   int64  `json:"max_billable"`
	MaxRecordOnly int64  `json:"max_record_only"`
	Replayed      bool   `json:"replayed"`
	SHA256        string `json:"sha256,omitempty"`
	Sequence      int    `json:"sequence,omitempty"`
}

func strict(raw []byte, out any) error {
	if _, err := Canonical(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
func VerifyOwner(s Signed, key ed25519.PublicKey, b Binding, operation string, request any) (json.RawMessage, error) {
	raw, err := Verify(s, key, true)
	if err != nil {
		return nil, err
	}
	var record OwnerRecord
	if err = strict(raw, &record); err != nil {
		return nil, err
	}
	h, err := Hash(request)
	if err != nil {
		return nil, err
	}
	if record.Kind != "owner-meter-v1" || record.Operation != operation || record.TenantID != b.TenantID || record.LeaseID != b.LeaseID || record.GatewayID != b.GatewayID || record.RequestSHA256 != h {
		return nil, ErrInvalid
	}
	return record.Result, nil
}

// LocalDeadline uses the protected monotonic sample from BEFORE the original
// request send, never response arrival or a retry. The caller must qualify the
// timer and its rate bound; time.Now from an ordinary host is not such a timer.
func LocalDeadline(g Grant, beforeSend, now time.Duration, driftPPM int64) (time.Duration, error) {
	if g.IssuedAt == nil || *g.IssuedAt < 0 || g.Deadline <= *g.IssuedAt || g.Deadline-*g.IssuedAt > 30 || g.Replayed || beforeSend < 0 || now < beforeSend || driftPPM < 0 || driftPPM > 10000 {
		return 0, ErrDisputed
	}
	span := time.Duration(g.Deadline-*g.IssuedAt-1) * time.Second
	span -= time.Duration(int64(span) * driftPPM / 1000000)
	if span <= 0 || beforeSend > time.Duration(1<<63-1)-span {
		return 0, ErrDisputed
	}
	deadline := beforeSend + span
	if now >= deadline {
		return 0, ErrDisputed
	}
	return deadline, nil
}
func VerifyGrant(s Signed, key ed25519.PublicKey, b Binding, operation string, request any, maxBillable, maxRecordOnly int64) (Grant, error) {
	var g Grant
	raw, err := VerifyOwner(s, key, b, operation, request)
	if err != nil {
		return g, err
	}
	if err = strict(raw, &g); err != nil {
		return g, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		return Grant{}, err
	}
	if operation == "start" && string(fields["replayed"]) != "false" {
		return Grant{}, ErrDisputed
	}
	if (operation != "start" && operation != "renew") || !uuidPattern.MatchString(g.StartID) || g.MaxBillable != maxBillable || g.MaxRecordOnly != maxRecordOnly || maxBillable < 0 || maxRecordOnly < 0 || g.IssuedAt == nil {
		return Grant{}, ErrInvalid
	}
	return g, nil
}
