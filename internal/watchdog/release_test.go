package watchdog

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/FyberLabs/hypermesh-host/internal/update"
)

func TestSignedReleaseProfileContract(t *testing.T) {
	manifest := []byte(`{"channel":"test","build":213,"version":"0.0.213","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_id":"213-aaaaaaaaaaaa"}`)
	checksums := []byte(fmt.Sprintf("%x  %s\n", sha256.Sum256(manifest), update.ManifestName))
	signature := []byte("fixture signature")
	pub := []byte("fixture key")
	fingerprints := []string{strings.Repeat("A", 40)}
	verify := func(_, sig, key []byte, allowed []string) error {
		if string(sig) != string(signature) || string(key) != string(pub) || len(allowed) != 1 || allowed[0] != fingerprints[0] {
			return errors.New("untrusted signature")
		}
		return nil
	}
	for _, target := range []struct {
		platform string
		arch     string
		channel  string
		minimum  int
		want     string
	}{
		{"linux", "amd64", "test", 213, "hypermesh-agent_0.0.213_linux_amd64"},
		{"linux", "arm64", "test", 213, "hypermesh-agent_0.0.213_linux_arm64"},
		{"darwin", "arm64", "test", 213, "hypermesh-agent_0.0.213_darwin_arm64"},
		{"darwin", "amd64", "test", 213, ""},
		{"linux", "amd64", "prod", 213, ""},
		{"linux", "arm64", "test", 214, ""},
	} {
		release, err := verifyRelease(checksums, signature, manifest, pub, fingerprints,
			target.channel, target.platform, target.arch, target.minimum, verify)
		if (err == nil) != (target.want != "") || release.Binary != target.want {
			t.Fatalf("%+v: %+v, %v", target, release, err)
		}
	}
	if _, err := verifyRelease(checksums, signature, append(manifest, ' '), pub, fingerprints,
		"test", "linux", "amd64", 213, verify); err == nil {
		t.Fatal("modified manifest accepted")
	}
	if _, err := verifyRelease(checksums, []byte("different signature"), manifest, pub, fingerprints,
		"test", "linux", "amd64", 213, verify); err == nil {
		t.Fatal("untrusted signature accepted")
	}
}
