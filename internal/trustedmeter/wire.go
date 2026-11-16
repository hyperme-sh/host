package trustedmeter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var measurementPattern = regexp.MustCompile(`^[0-9a-f]{96}$`)
var integerPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

const recordDomain = "hypermesh-trusted-meter-v1\x00"
const ownerDomain = "hypermesh-meter-owner-v1\x00"

type Binding struct {
	TenantID        string `json:"tenant_id"`
	LeaseID         string `json:"lease_id"`
	DeviceID        string `json:"device_id"`
	GatewayID       string `json:"gateway_id"`
	ModelSHA256     string `json:"model_sha256"`
	TokenizerSHA256 string `json:"tokenizer_sha256"`
	TemplateSHA256  string `json:"template_sha256"`
	RuntimeSHA256   string `json:"runtime_sha256"`
	Measurement     string `json:"measurement"`
	PolicySHA256    string `json:"policy_sha256"`
}

func (b Binding) Validate() error {
	for _, s := range []string{b.TenantID, b.LeaseID, b.DeviceID, b.GatewayID} {
		if !uuidPattern.MatchString(s) {
			return ErrInvalid
		}
	}
	for _, s := range []string{b.ModelSHA256, b.TokenizerSHA256, b.TemplateSHA256, b.RuntimeSHA256} {
		if !digestPattern.MatchString(s) {
			return ErrInvalid
		}
	}
	if !measurementPattern.MatchString(b.Measurement) || b.PolicySHA256 != PolicySHA256 {
		return ErrInvalid
	}
	return nil
}

type Start struct {
	Nonce   string  `json:"nonce"`
	Kind    string  `json:"kind"`
	Binding Binding `json:"binding"`
	Epoch   string  `json:"epoch"`
	BatchID string  `json:"batch_id"`
}
type Checkpoint struct {
	Kind           string   `json:"kind"`
	Binding        Binding  `json:"binding"`
	Epoch          string   `json:"epoch"`
	BatchID        string   `json:"batch_id"`
	StartID        string   `json:"start_id"`
	Sequence       int      `json:"sequence"`
	PreviousSHA256 string   `json:"previous_sha256"`
	Counters       Counters `json:"counters"`
	Outcome        string   `json:"outcome"`
}

func (c Checkpoint) Validate() error {
	if c.Binding.Validate() != nil || c.Kind != "checkpoint-v1" || !uuidPattern.MatchString(c.Epoch) || !uuidPattern.MatchString(c.BatchID) || !uuidPattern.MatchString(c.StartID) || c.Sequence < 1 || c.Sequence > 256 || !digestPattern.MatchString(c.PreviousSHA256) {
		return ErrInvalid
	}
	if _, err := c.Counters.Billable(); err != nil {
		return err
	}
	switch c.Outcome {
	case "running", "completed", "interrupted":
	case "no_work":
		if c.Counters != (Counters{}) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if c.Sequence == 256 && c.Outcome == "running" {
		return ErrInvalid
	}
	return nil
}

type Signed struct {
	Record    json.RawMessage `json:"record"`
	Signature string          `json:"signature"`
}

// parse rejects duplicate keys, floats, oversized integers and non-ASCII strings.
// The count protocol has no free-form text; this is Python canonical JSON's ASCII subset.
func parse(d *json.Decoder, depth int) (any, error) {
	if depth > 12 {
		return nil, ErrInvalid
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := t.(type) {
	case json.Delim:
		if v == '{' {
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				key, ok := k.(string)
				if !ok {
					return nil, ErrInvalid
				}
				if _, ok = m[key]; ok {
					return nil, ErrInvalid
				}
				for _, c := range key {
					if c > 127 {
						return nil, ErrInvalid
					}
				}
				x, e := parse(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[key] = x
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return m, nil
		}
		if v == '[' {
			a := []any{}
			for d.More() {
				x, e := parse(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, x)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return a, nil
		}
		return nil, ErrInvalid
	case json.Number:
		if !integerPattern.MatchString(string(v)) {
			return nil, ErrInvalid
		}
		if _, e := strconv.ParseInt(string(v), 10, 64); e != nil {
			return nil, ErrInvalid
		}
		return v, nil
	case string:
		for _, c := range v {
			if c > 127 {
				return nil, ErrInvalid
			}
		}
		return v, nil
	case bool, nil:
		return v, nil
	default:
		return nil, ErrInvalid
	}
}
func Canonical(raw []byte) ([]byte, error) {
	if len(raw) > 16384 {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := parse(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrInvalid
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if e = enc.Encode(v); e != nil {
		return nil, e
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}
func canonicalValue(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return Canonical(b)
}
func Hash(v any) (string, error) {
	b, e := canonicalValue(v)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func Sign(v any, key ed25519.PrivateKey) (Signed, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Signed{}, ErrInvalid
	}
	b, e := canonicalValue(v)
	if e != nil {
		return Signed{}, e
	}
	return Signed{b, hex.EncodeToString(ed25519.Sign(key, append([]byte(recordDomain), b...)))}, nil
}
func Verify(s Signed, key ed25519.PublicKey, owner bool) ([]byte, error) {
	b, e := Canonical(s.Record)
	if e != nil {
		return nil, e
	}
	sig, e := hex.DecodeString(s.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize || len(key) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	domain := recordDomain
	if owner {
		domain = ownerDomain
	}
	if !ed25519.Verify(key, append([]byte(domain), b...), sig) {
		return nil, fmt.Errorf("%w: signature", ErrInvalid)
	}
	return b, nil
}

func NewStart(b Binding, epoch, batch string) (Start, error) {
	if b.Validate() != nil || !uuidPattern.MatchString(epoch) || !uuidPattern.MatchString(batch) {
		return Start{}, ErrInvalid
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return Start{}, err
	}
	return Start{Kind: "start-v2", Binding: b, Epoch: epoch, BatchID: batch, Nonce: hex.EncodeToString(nonce)}, nil
}
