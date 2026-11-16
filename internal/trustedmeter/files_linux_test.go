package trustedmeter

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSealedFileCannotChangeAfterDigestCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "untrusted")
	original := []byte("approved bytes")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	hash := sha256.Sum256(original)
	expected := hex.EncodeToString(hash[:])
	sealed, err := SealFile(source, expected, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	if err = os.WriteFile(path, []byte("changed source"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(sealed)
	if err != nil || string(got) != string(original) {
		t.Fatal(string(got), err)
	}
	if _, err = sealed.WriteAt([]byte("tamper"), 0); err == nil {
		t.Fatal("sealed write succeeded")
	}
	if err = sealed.Truncate(0); err == nil {
		t.Fatal("sealed truncate succeeded")
	}
	if _, err = SealFile(source, expected, 1024); err == nil {
		t.Fatal("modified source accepted")
	}
}
