package trustedmeter

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
)

type retirement struct {
	BatchID    string `json:"batch_id"`
	RuntimeKey string `json:"runtime_key"`
	Operation  string `json:"operation"`
	Proof      Signed `json:"proof"`
}

// Only signed owner recovery or no-start cancellation allows local history
// deletion. Plane retains the immutable terminal record and replay authority.
func (s *Server) retire(w http.ResponseWriter, r *http.Request) {
	if !s.execution.TryLock() {
		refuse(w, 409)
		return
	}
	defer s.execution.Unlock()
	raw, err := readBody(r, 16384)
	var request retirement
	if err != nil || strict(raw, &request) != nil {
		refuse(w, 400)
		return
	}
	if err = s.retireHistory(request); err != nil {
		refuse(w, 409)
		return
	}
	reply(w, map[string]bool{"retired": true})
}
func (s *Server) retireHistory(request retirement) error {
	if !uuidPattern.MatchString(request.BatchID) || !digestPattern.MatchString(request.RuntimeKey) || (request.Operation != "recover" && request.Operation != "cancel") {
		return ErrInvalid
	}
	raw, err := VerifyOwner(request.Proof, s.owner, s.binding, request.Operation, map[string]string{"batch_id": request.BatchID})
	if err != nil {
		return err
	}
	var terminal string
	var recovered Counters
	if request.Operation == "recover" {
		var result struct {
			BatchID        string   `json:"batch_id"`
			TerminalSHA256 string   `json:"terminal_sha256"`
			Counters       Counters `json:"counters"`
			Billable       int64    `json:"billable"`
			PolicySHA256   string   `json:"policy_sha256"`
		}
		if strict(raw, &result) != nil || result.BatchID != request.BatchID || result.PolicySHA256 != PolicySHA256 {
			return ErrInvalid
		}
		billable, err := result.Counters.Billable()
		if err != nil || billable != result.Billable {
			return ErrInvalid
		}
		terminal = result.TerminalSHA256
		recovered = result.Counters
	} else {
		var result struct {
			BatchID        string `json:"batch_id"`
			TerminalSHA256 string `json:"terminal_sha256"`
		}
		if strict(raw, &result) != nil || result.BatchID != request.BatchID {
			return ErrInvalid
		}
		terminal = result.TerminalSHA256
	}
	if !digestPattern.MatchString(terminal) {
		return ErrInvalid
	}
	path := filepath.Join(s.stateDir, request.RuntimeKey+"-"+request.BatchID+".json")
	if _, err = os.Lstat(path); err != nil && !os.IsNotExist(err) {
		return err
	} else if err == nil {
		key, _ := hex.DecodeString(request.RuntimeKey)
		journal, err := OpenJournal(path, s.binding, ed25519.PublicKey(key))
		if err != nil {
			return err
		}
		entry, err := journal.Status(s.binding, request.BatchID)
		if err != nil {
			return err
		}
		if request.Operation == "recover" {
			if entry.Phase != "terminal" || len(entry.Records) == 0 {
				return ErrDisputed
			}
			final := entry.Records[len(entry.Records)-1]
			hash, err := Hash(final.Record)
			if err != nil || hash != terminal {
				return ErrInvalid
			}
			var checkpoint Checkpoint
			if strict(final.Record, &checkpoint) != nil || checkpoint.Counters != recovered {
				return ErrInvalid
			}
		} else {
			if entry.Phase != "starting" || entry.StartID != "" || len(entry.Records) != 0 {
				return ErrDisputed
			}
			hash, err := Hash(map[string]any{"kind": "owner-no-start-v1", "binding": s.binding, "epoch": entry.Epoch, "batch_id": entry.BatchID, "counters": Counters{}, "outcome": "no_work"})
			if err != nil || hash != terminal {
				return ErrInvalid
			}
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	directory, err := os.Open(s.stateDir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
