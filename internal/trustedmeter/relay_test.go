package trustedmeter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRelayPinsOwnerAuthorizedPeerAndUsesGuestTLSKey(t *testing.T) {
	peer, peerKey, _ := ed25519.GenerateKey(rand.Reader)
	runtime, runtimeKey, _ := ed25519.GenerateKey(rand.Reader)
	certificate, err := guestCertificateForRelayTest(peerKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := guestCertificateForRelayTest(runtimeKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, err := tlsPeerKey(*r.TLS)
		if err != nil || !key.Equal(runtime) {
			t.Error("wrong guest TLS key", err)
			w.WriteHeader(403)
			return
		}
		if r.URL.Path != "/trusted-meter/relay" {
			t.Error(r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(Signed{Record: json.RawMessage(`{}`), Signature: "test"})
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	relay, err := NewRelay(server.URL+"/trusted-meter/relay", binding(), clientCertificate, peer)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	if _, err = relay.Exchange(context.Background(), "start", Signed{Record: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	bad, err := NewRelay(server.URL+"/trusted-meter/relay", binding(), clientCertificate, wrong)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if _, err = bad.Exchange(context.Background(), "start", Signed{Record: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("untrusted relay key accepted")
	}
}

func guestCertificateForRelayTest(key ed25519.PrivateKey) (tls.Certificate, error) {
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Unix(0, 0), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, err
}
