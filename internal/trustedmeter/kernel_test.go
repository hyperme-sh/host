package trustedmeter

import (
	"strings"
	"testing"
)

func TestKernelProfileRequiresBuiltInIsolationAndForbidsUnmeasuredLoading(t *testing.T) {
	var config strings.Builder
	for _, name := range kernelRequired {
		config.WriteString("CONFIG_" + name + "=y\n")
	}
	if err := ValidateKernelConfig(config.String()); err != nil {
		t.Fatal(err)
	}
	for _, name := range kernelForbidden {
		if ValidateKernelConfig(config.String()+"CONFIG_"+name+"=y\n") == nil {
			t.Fatal("unsafe feature", name)
		}
	}
	if ValidateKernelConfig(strings.ReplaceAll(config.String(), "CONFIG_SEV_GUEST=y", "CONFIG_SEV_GUEST=m")) == nil {
		t.Fatal("unmeasured module")
	}
}
