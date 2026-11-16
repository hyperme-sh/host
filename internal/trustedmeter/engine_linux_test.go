package trustedmeter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestCPUProtocolStartsAfterLoadAndRenewsAtBoundary(t *testing.T) {
	c, owner, _ := controller(t)
	// This is a unit fixture for the private pipe, not a model runtime.
	script := `#!/bin/sh
read -r request
echo '{"event":"permit","kind":"input","count":5}'
read -r permit
echo '{"event":"counts","processed_input":5,"accepted_output":0,"hidden_output":0,"cache_hits":0,"rejected_speculative":0}'
echo '{"event":"permit","kind":"output","count":1}'
read -r permit
echo '{"event":"counts","processed_input":5,"accepted_output":1,"hidden_output":0,"cache_hits":0,"rejected_speculative":0}'
echo '{"event":"output","hex":"6869"}'
echo '{"event":"completed"}'
`
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
	files.Binary, c.binding.RuntimeSHA256 = makeFile("mock-engine", script)
	files.Model, c.binding.ModelSHA256 = makeFile("model", "mock model")
	files.Template, c.binding.TemplateSHA256 = makeFile("template", "mock template")
	c.binding.TokenizerSHA256 = c.binding.ModelSHA256
	c.journal.data.Binding = c.binding
	owner.advanceCheckpoint = 20 * time.Second
	var out bytes.Buffer
	if err := runCPU(context.Background(), c, files, []byte(`{"messages":[],"max_tokens":1}`), &out, false); err != nil {
		t.Fatal(err)
	}
	if out.String() != "hi" {
		t.Fatal(out.String())
	}
	expected := []string{"start", "checkpoint", "renew", "checkpoint", "checkpoint"}
	if len(owner.calls) != len(expected) {
		t.Fatal(owner.calls)
	}
	for i, v := range expected {
		if owner.calls[i] != v {
			t.Fatal(owner.calls)
		}
	}
}
