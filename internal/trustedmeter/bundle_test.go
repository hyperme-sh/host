package trustedmeter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func launchFixture(t *testing.T) (string, string, Binding, Bundle) {
	t.Helper()
	dir := t.TempDir()
	model := filepath.Join(t.TempDir(), "model.gguf")
	modelBytes := []byte("unit model bytes")
	sum := sha256.Sum256(modelBytes)
	b := binding()
	b.ModelSHA256 = hex.EncodeToString(sum[:])
	b.TokenizerSHA256 = b.ModelSHA256
	if err := os.WriteFile(model, modelBytes, 0600); err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{Schema: 1, Profile: GuestProfile{OwnerKey: strings.Repeat("f", 64), ModelSHA256: b.ModelSHA256, TokenizerSHA256: b.TokenizerSHA256, TemplateSHA256: b.TemplateSHA256, RuntimeSHA256: b.RuntimeSHA256, PolicySHA256: b.PolicySHA256, DriftPPM: 100}, Measurement: b.Measurement, CBitPos: 51, ReducedPhysBits: 1, MemoryMiB: 4096, TSCFrequencyKHz: 2400000}
	for name, ptr := range map[string]*string{"firmware.fd": &bundle.FirmwareSHA256, "kernel": &bundle.KernelSHA256, "initrd.cpio": &bundle.InitrdSHA256} {
		raw := []byte("unit " + name)
		h := sha256.Sum256(raw)
		*ptr = hex.EncodeToString(h[:])
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(bundle)
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return dir, model, b, bundle
}
func TestTrustedLaunchStagesOnlyBoundArtifactsAndKeepsJournal(t *testing.T) {
	dir, model, b, _ := launchFixture(t)
	state := t.TempDir()
	_, args, err := PrepareLaunch(dir, state, b, model, 18443)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"kernel-hashes=on", "secure-tsc=on", "policy=0x30000", "tsc-frequency=2400000", "-smp 1", "-monitor none", "readonly=on", "127.0.0.1:18443-:8443"} {
		if !strings.Contains(joined, want) {
			t.Fatal(want)
		}
	}
	root, _ := LeaseDirectory(state, b.LeaseID)
	loaded, err := LoadBinding(filepath.Join(root, "input", "binding.json"))
	if err != nil || loaded != b {
		t.Fatal(loaded, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "input"))
	if err != nil || len(entries) != 2 {
		t.Fatal(entries, err)
	}
	record := filepath.Join(root, "journal", "record.json")
	if err = os.WriteFile(record, []byte("unit"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = CleanStoppedLaunch(state, b.LeaseID); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(record); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(root, "boot")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
func TestTrustedLaunchRejectsChangedArtifactsAndScope(t *testing.T) {
	for _, name := range []string{"firmware.fd", "kernel", "initrd.cpio", "model"} {
		t.Run(name, func(t *testing.T) {
			dir, model, b, _ := launchFixture(t)
			target := filepath.Join(dir, name)
			if name == "model" {
				target = model
			}
			if err := os.WriteFile(target, []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := PrepareLaunch(dir, t.TempDir(), b, model, 18443); err == nil {
				t.Fatal("changed artifact accepted")
			}
		})
	}
	dir, _, b, bundle := launchFixture(t)
	b.Measurement = strings.Repeat("f", 96)
	if _, err := LoadBundle(dir, b); err == nil {
		t.Fatal("wrong measurement")
	}
	if _, err := LaunchArgs(bundle, "/tmp/a,host=bad", "/tmp/input", "/tmp/journal", 18443); err == nil {
		t.Fatal("QEMU option injection")
	}
	if _, err := LeaseDirectory("/tmp", "../other"); err == nil {
		t.Fatal("path escape")
	}
}
