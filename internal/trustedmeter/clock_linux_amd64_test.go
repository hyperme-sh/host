package trustedmeter

import "testing"

func TestClockRejectsSNPWithoutSecureTSCAndFallbackSources(t *testing.T) {
	for _, status := range []uint64{0, 1 << 2, 1 << 11} {
		if secureClockStatus(status, "tsc") == nil {
			t.Fatal("unsupported clock", status)
		}
	}
	for _, source := range []string{"kvm-clock", "hpet", "acpi_pm", ""} {
		if secureClockStatus(1<<2|1<<11, source) == nil {
			t.Fatal("host-influenced clock", source)
		}
	}
	if err := secureClockStatus(1<<2|1<<11, "tsc\n"); err != nil {
		t.Fatal(err)
	}
}
