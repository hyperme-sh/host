package trustedmeter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
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
	server := &Server{channels: channels, binding: binding(), key: key, stateDir: dir}
	journal, err := server.requestJournal(pub, batch)
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
	// A separately authorized new guest serves the original journal only.
	server.channels, _ = NewChannels(binding(), newKey.Public().(ed25519.PublicKey), owner, clock, 1000)
	response = call("/history/channels/challenge", "", HistoryScope{batch, hex.EncodeToString(pub)}, peer)
	var historical HistoryChannelRequest
	if json.Unmarshal(response.Body.Bytes(), &historical) != nil || response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	response = call("/history/channels/authorize", "", map[string]any{"nonce": historical.Nonce, "proof": historyProof(t, ownerKey, historical)}, peer)
	if json.Unmarshal(response.Body.Bytes(), &authorization) != nil || response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	response = call("/status", authorization["channel"], body, peer)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	for _, path := range []string{"/quote", "/execute"} {
		if call(path, authorization["channel"], body, peer).Code != 403 {
			t.Fatal("historical access to", path)
		}
	}
	if call("/status", authorization["channel"], map[string]string{"batch_id": epoch, "runtime_key": hex.EncodeToString(pub)}, peer).Code != 403 {
		t.Fatal("other batch access")
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

func TestGuestHistoryPartitionsSurviveBeyondFormerLifetimeLimit(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	server := &Server{binding: binding(), key: key, stateDir: t.TempDir()}
	for n := 0; n < 140; n++ {
		id := fmt.Sprintf("%08x-5555-5555-5555-555555555555", n)
		journal, err := server.requestJournal(pub, id)
		if err != nil {
			t.Fatal(err)
		}
		if err = journal.Begin(id, epoch); err != nil {
			t.Fatal(n, err)
		}
		if err = journal.Started(id, start); err != nil {
			t.Fatal(err)
		}
		record := checkpoint()
		record.BatchID = id
		final, err := Sign(record, key)
		if err != nil {
			t.Fatal(err)
		}
		if err = journal.Append(id, final); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []int{0, 128, 139} {
		id := fmt.Sprintf("%08x-5555-5555-5555-555555555555", n)
		journal, err := server.requestJournal(pub, id)
		if err != nil {
			t.Fatal(err)
		}
		status, err := journal.Status(binding(), id)
		if err != nil || status.Phase != "terminal" || len(status.Records) != 1 {
			t.Fatal(status, err)
		}
		if journal.Begin(id, epoch) == nil {
			t.Fatal("duplicate request resumed")
		}
	}
}
