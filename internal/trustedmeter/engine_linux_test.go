package trustedmeter

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestEngineFilesRejectAlteredModelAndSeparateTokenizer(t *testing.T) {
	b := binding()
	makeFile := func(name, content string) (*os.File, string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(content), 0500); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		hash := sha256.Sum256([]byte(content))
		return f, hex.EncodeToString(hash[:])
	}
	var files EngineFiles
	files.Binary, b.RuntimeSHA256 = makeFile("engine", "measured engine")
	files.Model, b.ModelSHA256 = makeFile("model", "model and embedded tokenizer")
	files.Template, b.TemplateSHA256 = makeFile("template", "fixed template")
	b.TokenizerSHA256 = b.ModelSHA256
	if err := files.Verify(b); err != nil {
		t.Fatal(err)
	}
	b.TokenizerSHA256 = b.RuntimeSHA256
	if files.Verify(b) == nil {
		t.Fatal("separate tokenizer accepted")
	}
	b.TokenizerSHA256 = b.ModelSHA256
	if err := os.Chmod(files.Model.Name(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files.Model.Name(), []byte("altered"), 0700); err != nil {
		t.Fatal(err)
	}
	if files.Verify(b) == nil {
		t.Fatal("changed model accepted")
	}
}
