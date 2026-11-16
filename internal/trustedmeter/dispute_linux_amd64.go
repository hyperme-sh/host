package trustedmeter

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
)

// DisputeArchive describes the count-only snapshot Plane must durably archive
// before signing retirement. The final record hash commits the verified chain,
// including records whose owner acknowledgement was lost.
type DisputeArchive struct {
	Kind             string  `json:"kind"`
	Binding          Binding `json:"binding"`
	RuntimeKey       string  `json:"runtime_key"`
	BatchID          string  `json:"batch_id"`
	Epoch            string  `json:"epoch"`
	StartID          string  `json:"start_id"`
	Phase            string  `json:"phase"`
	Sequence         int     `json:"sequence"`
	LastRecordSHA256 string  `json:"last_record_sha256"`
}

type disputeArchiveResult struct {
	BatchID            string `json:"batch_id"`
	RuntimeKey         string `json:"runtime_key"`
	ArchiveSHA256      string `json:"archive_sha256"`
	LastAnchorSequence int    `json:"last_anchor_sequence"`
	LastAnchorSHA256   string `json:"last_anchor_sha256"`
	Status             string `json:"status"`
}

func archiveManifest(b Binding, key ed25519.PublicKey, entry Entry) (DisputeArchive, error) {
	manifest := DisputeArchive{"archived-dispute-v1", b, hex.EncodeToString(key), entry.BatchID, entry.Epoch, entry.StartID, entry.Phase, len(entry.Records), strings.Repeat("0", 64)}
	if entry.Phase != "starting" && entry.Phase != "running" && entry.Phase != "terminal" {
		return manifest, ErrDisputed
	}
	if len(entry.Records) > 0 {
		hash, err := Hash(entry.Records[len(entry.Records)-1].Record)
		if err != nil {
			return manifest, err
		}
		manifest.LastRecordSHA256 = hash
	}
	return manifest, nil
}

func (s *Server) verifyDisputeArchive(request retirement) (disputeArchiveResult, error) {
	var result disputeArchiveResult
	raw, err := VerifyOwner(request.Proof, s.owner, s.binding, "archive-dispute", map[string]string{"batch_id": request.BatchID, "runtime_key": request.RuntimeKey})
	if err != nil {
		return result, err
	}
	if strict(raw, &result) != nil || result.BatchID != request.BatchID || result.RuntimeKey != request.RuntimeKey || result.Status != "disputed" || !digestPattern.MatchString(result.ArchiveSHA256) || !digestPattern.MatchString(result.LastAnchorSHA256) || result.LastAnchorSequence < 0 || result.LastAnchorSequence > 256 {
		return result, ErrInvalid
	}
	if result.LastAnchorSequence == 0 && result.LastAnchorSHA256 != strings.Repeat("0", 64) {
		return result, ErrInvalid
	}
	return result, nil
}

func (s *Server) matchDisputeArchive(request retirement, entry Entry, result disputeArchiveResult) error {
	key, _ := hex.DecodeString(request.RuntimeKey)
	manifest, err := archiveManifest(s.binding, key, entry)
	if err != nil {
		return err
	}
	hash, err := Hash(manifest)
	if err != nil || hash != result.ArchiveSHA256 || result.LastAnchorSequence > len(entry.Records) {
		return ErrInvalid
	}
	// An owner-anchored terminal must use ordinary recovery. A local terminal
	// lost before owner acceptance can still be archived as disputed.
	if entry.Phase == "terminal" && result.LastAnchorSequence >= len(entry.Records) {
		return ErrDisputed
	}
	if result.LastAnchorSequence > 0 {
		hash, err = Hash(entry.Records[result.LastAnchorSequence-1].Record)
		if err != nil || hash != result.LastAnchorSHA256 {
			return ErrInvalid
		}
	}
	return nil
}
