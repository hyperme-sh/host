package hardware

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStrixHaloVulkanBudget(t *testing.T) {
	p := Recommend(Facts{Vulkan: true, StrixHaloGTTFreeBytes: 64 << 30, AvailableBytes: 32 << 30})
	if p.Backend != "vulkan" || p.ModelBudgetBytes != 24<<30 {
		t.Fatalf("unexpected Vulkan budget: %d bytes (%s)", p.ModelBudgetBytes, p.Backend)
	}
}

func TestStrixHaloGTTRequiresMatchingHardwareAndCounters(t *testing.T) {
	device := t.TempDir()
	for name, value := range map[string]string{
		"vendor": "0x1002", "device": "0x1586", "mem_info_gtt_total": "8192", "mem_info_gtt_used": "4096",
	} {
		if err := os.WriteFile(filepath.Join(device, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got := strixHaloGTTAt(device); got != 4096 {
		t.Fatalf("free GTT = %d", got)
	}
	if err := os.WriteFile(filepath.Join(device, "device"), []byte("0x1234"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := strixHaloGTTAt(device); got != 0 {
		t.Fatalf("unrecognized device reported %d bytes", got)
	}
}
