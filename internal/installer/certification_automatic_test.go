//go:build linux || darwin

package installer

import (
	"strings"
	"testing"
)

func TestAutomaticNativeInputs(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, registration, model, binary string
		valid                             bool
	}{
		{name: "missing"},
		{name: "invalid digest", registration: "approved", model: "/var/lib/model.gguf", binary: "/usr/bin/llama-bench"},
		{name: "relative model", registration: digest, model: "model.gguf", binary: "/usr/bin/llama-bench"},
		{name: "relative runtime", registration: digest, model: "/var/lib/model.gguf", binary: "llama-bench"},
		{name: "provisioned", registration: digest, model: "/var/lib/model.gguf", binary: "/usr/bin/llama-bench", valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HYPERMESH_NATIVE_REGISTRATION_PLAN_SHA", test.registration)
			t.Setenv("HYPERMESH_NATIVE_MODEL_FILE", test.model)
			t.Setenv("HYPERMESH_NATIVE_RUNTIME_FILE", test.binary)
			registration, model, binary, err := automaticNativeInputs()
			if (err == nil) != test.valid {
				t.Fatalf("unexpected validation result: %v", err)
			}
			if test.valid && (registration != test.registration || model != test.model || binary != test.binary) {
				t.Fatal("provisioned inputs changed")
			}
		})
	}
}

func TestMissingNativeInputFileUsesEnvironment(t *testing.T) {
	digest := strings.Repeat("a", 64)
	t.Setenv("HYPERMESH_NATIVE_REGISTRATION_PLAN_SHA", digest)
	t.Setenv("HYPERMESH_NATIVE_MODEL_FILE", "/var/lib/model.gguf")
	t.Setenv("HYPERMESH_NATIVE_RUNTIME_FILE", "/usr/bin/llama-bench")
	inputs, err := readNativeProvisionedInputs(t.TempDir())
	if err != nil || inputs.Registration != digest || inputs.Model != "/var/lib/model.gguf" {
		t.Fatalf("expected provisioned environment fallback: %v", err)
	}
}
