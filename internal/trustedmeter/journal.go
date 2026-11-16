package trustedmeter

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Entry struct {
	BatchID string   `json:"batch_id"`
	Epoch   string   `json:"epoch"`
	Phase   string   `json:"phase"`
	StartID string   `json:"start_id"`
	Records []Signed `json:"records"`
}
type diskJournal struct {
	Binding    Binding          `json:"binding"`
	RuntimeKey []byte           `json:"runtime_key"`
	Entries    map[string]Entry `json:"entries"`
}

// Journal holds no private key or inference payload. Loading it is read-only:
// an interrupted process may expose status but must never resume execution.
type Journal struct {
	mu       sync.Mutex
	path     string
	data     diskJournal
	reopened bool
	failed   bool
}

func OpenJournal(path string, b Binding, key ed25519.PublicKey) (*Journal, error) {
	if b.Validate() != nil || len(key) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	j := &Journal{path: path, data: diskJournal{b, append([]byte{}, key...), map[string]Entry{}}}
	f, err := os.Open(path)
	var raw []byte
	if err == nil {
		raw, err = io.ReadAll(io.LimitReader(f, (8<<20)+1))
		f.Close()
	}
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 8<<20 {
		return nil, ErrInvalid
	}
	// The journal is larger than a single wire record, so decode its structure
	// separately, then verify every bounded signed record and all identities.
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err = d.Decode(&j.data); err != nil {
		return nil, err
	}
	if j.data.Binding != b || !ed25519.PublicKey(j.data.RuntimeKey).Equal(key) || len(j.data.Entries) > 128 {
		return nil, ErrInvalid
	}
	for id, e := range j.data.Entries {
		if id != e.BatchID || !uuidPattern.MatchString(id) || !uuidPattern.MatchString(e.Epoch) || len(e.Records) > 256 {
			return nil, ErrInvalid
		}
		if err = j.validate(e); err != nil {
			return nil, err
		}
	}
	j.reopened = true
	return j, nil
}
func (j *Journal) validate(e Entry) error {
	if e.Phase != "starting" && e.Phase != "running" && e.Phase != "terminal" {
		return ErrInvalid
	}
	previous := strings.Repeat("0", 64)
	prior := Counters{}
	for i, s := range e.Records {
		raw, err := Verify(s, j.data.RuntimeKey, false)
		if err != nil {
			return err
		}
		var c Checkpoint
		if err = strict(raw, &c); err != nil {
			return err
		}
		if c.Validate() != nil || c.Binding != j.data.Binding || c.BatchID != e.BatchID || c.Epoch != e.Epoch || c.StartID != e.StartID || c.Sequence != i+1 || c.PreviousSHA256 != previous {
			return ErrInvalid
		}
		a := []int64{c.Counters.ProcessedInput, c.Counters.AcceptedOutput, c.Counters.HiddenOutput, c.Counters.CacheHits, c.Counters.RejectedSpeculative}
		p := []int64{prior.ProcessedInput, prior.AcceptedOutput, prior.HiddenOutput, prior.CacheHits, prior.RejectedSpeculative}
		for k := range a {
			if a[k] < p[k] {
				return ErrInvalid
			}
		}
		if i < len(e.Records)-1 && c.Outcome != "running" {
			return ErrInvalid
		}
		if i == len(e.Records)-1 && ((e.Phase == "terminal") != (c.Outcome != "running")) {
			return ErrInvalid
		}
		previous, err = Hash(c)
		if err != nil {
			return err
		}
		prior = c.Counters
	}
	if e.Phase == "terminal" && len(e.Records) == 0 {
		return ErrInvalid
	}
	if e.Phase != "starting" && !uuidPattern.MatchString(e.StartID) {
		return ErrInvalid
	}
	return nil
}
func (j *Journal) save() error {
	if j.failed {
		return ErrDisputed
	}
	raw, err := json.Marshal(j.data)
	if err != nil {
		return err
	}
	if len(raw) > 8<<20 {
		return ErrInvalid
	}
	dir := filepath.Dir(j.path)
	f, err := os.CreateTemp(dir, ".meter-")
	if err != nil {
		j.failed = true
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, j.path)
	}
	if err == nil {
		var d *os.File
		d, err = os.Open(dir)
		if err == nil {
			err = d.Sync()
			d.Close()
		}
	}
	if err != nil {
		j.failed = true
	}
	return err
}
func (j *Journal) Begin(batch, epoch string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.reopened || j.failed || !uuidPattern.MatchString(batch) || !uuidPattern.MatchString(epoch) {
		return ErrDisputed
	}
	if _, ok := j.data.Entries[batch]; ok {
		return ErrDisputed
	}
	if len(j.data.Entries) >= 128 {
		return ErrInvalid
	}
	j.data.Entries[batch] = Entry{BatchID: batch, Epoch: epoch, Phase: "starting", Records: []Signed{}}
	return j.save()
}
func (j *Journal) Started(batch, startID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	e, ok := j.data.Entries[batch]
	if j.reopened || j.failed || !ok || e.Phase != "starting" || !uuidPattern.MatchString(startID) {
		return ErrDisputed
	}
	e.Phase = "running"
	e.StartID = startID
	j.data.Entries[batch] = e
	return j.save()
}
func (j *Journal) Append(batch string, s Signed) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	e, ok := j.data.Entries[batch]
	if j.reopened || j.failed || !ok || e.Phase != "running" {
		return ErrDisputed
	}
	var c Checkpoint
	raw, err := Verify(s, j.data.RuntimeKey, false)
	if err != nil {
		return err
	}
	if err = strict(raw, &c); err != nil {
		return err
	}
	e.Records = append(append([]Signed{}, e.Records...), Signed{append(json.RawMessage{}, s.Record...), s.Signature})
	if c.Outcome != "running" {
		e.Phase = "terminal"
	}
	if err = j.validate(e); err != nil {
		return fmt.Errorf("%w: journal continuity", err)
	}
	j.data.Entries[batch] = e
	return j.save()
}
func (j *Journal) Status(b Binding, batch string) (Entry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if b != j.data.Binding || j.failed {
		return Entry{}, ErrInvalid
	}
	e, ok := j.data.Entries[batch]
	if !ok {
		return Entry{}, ErrDisputed
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	var out Entry
	err = json.Unmarshal(raw, &out)
	return out, err
}
