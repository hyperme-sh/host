package trustedmeter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestGuestStatusRequiresOwnerChannelAndReplaysOriginalFinal(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	owner, ownerKey, _ := ed25519.GenerateKey(rand.Reader)
	peer, _, _ := ed25519.GenerateKey(rand.Reader)
	clock := &fakeClock{time.Second}
	channels, _ := NewChannels(binding(), pub, owner, clock, 1000)
	dir := t.TempDir()
	journal, err := OpenJournal(filepath.Join(dir, hex.EncodeToString(pub)+".json"), binding(), pub)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Begin(batch, epoch) != nil || journal.Started(batch, start) != nil {
		t.Fatal("journal start")
	}
	final, _ := Sign(checkpoint(), key)
	if err = journal.Append(batch, final); err != nil {
		t.Fatal(err)
	}
	server := &Server{channels: channels, binding: binding(), key: key, stateDir: dir, journal: journal}
	call := func(path, token string, body any, tlsKey ed25519.PublicKey) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		request := httptest.NewRequest("POST", path, bytes.NewReader(raw))
		request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{{PublicKey: tlsKey}}}
		request.Header.Set("X-Hypermesh-Meter-Channel", token)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response
	}
	body := map[string]string{"batch_id": batch, "runtime_key": hex.EncodeToString(pub)}
	if call("/status", "", body, peer).Code != 403 {
		t.Fatal("unauthorized status")
	}
	response := call("/channels/challenge", "", map[string]string{}, peer)
	var challenge ChannelRequest
	if json.Unmarshal(response.Body.Bytes(), &challenge) != nil || response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	proof := channelProof(t, ownerKey, challenge)
	response = call("/channels/authorize", "", map[string]any{"nonce": challenge.Nonce, "proof": proof}, peer)
	var authorization map[string]string
	if json.Unmarshal(response.Body.Bytes(), &authorization) != nil || response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	response = call("/status", authorization["channel"], body, peer)
	var status Entry
	if json.Unmarshal(response.Body.Bytes(), &status) != nil || response.Code != 200 || status.Records[0].Signature != final.Signature {
		t.Fatal(response.Body.String())
	}
	// Simulate a new process key: historical records stay public-key-verifiable.
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	server.key = newKey
	response = call("/status", authorization["channel"], body, peer)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if call("/status", authorization["channel"], body, other).Code != 403 {
		t.Fatal("channel transferred")
	}
	clock.now = 31 * time.Second
	if call("/status", authorization["channel"], body, peer).Code != 403 {
		t.Fatal("expired status access")
	}
}
func TestExecutionPayloadRejectsDuplicatesAndPreservesUnicode(t *testing.T) {
	valid := executionRequest{BatchID: batch, Epoch: epoch, MaxBillable: 100, MaxRecordOnly: 0, RelayURL: "https://gateway/trusted-meter/relay", Messages: []message{{"user", "héllo 世界"}}, MaxTokens: 4}
	raw, _ := json.Marshal(valid)
	got, err := decodeExecution(raw)
	if err != nil || got.Messages[0].Content != valid.Messages[0].Content {
		t.Fatal(got, err)
	}
	duplicate := append([]byte(`{"max_tokens":128,`), raw[1:]...)
	if _, err = decodeExecution(duplicate); err == nil {
		t.Fatal("duplicate generation limit")
	}
	valid.MaxTokens = 129
	raw, _ = json.Marshal(valid)
	if _, err = decodeExecution(raw); err == nil {
		t.Fatal("unbounded output")
	}
}
