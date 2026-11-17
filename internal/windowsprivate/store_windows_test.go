//go:build windows

package windowsprivate

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"testing"
	"time"
)

func TestPrivateStoreRoundTripAndACLRefusal(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	descriptor := "O:" + sid + "G:" + sid + "D:P(A;;KA;;;" + sid + ")"
	path := fmt.Sprintf(`Software\HypermeshCrashUnit%d`, time.Now().UnixNano())
	k, err := openKey(registry.CURRENT_USER, path, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, path)
	defer k.Close()
	if err := Write(k, "test", []byte("private unit fixture")); err != nil {
		t.Fatal(err)
	}
	raw, _, err := k.GetBinaryValue("test")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "private unit fixture" {
		t.Fatal("plaintext checkpoint")
	}
	decoded, err := Read(k, "test")
	if err != nil || string(decoded) != "private unit fixture" {
		t.Fatal("round trip failed", err)
	}
	if _, err := openKey(registry.CURRENT_USER, path, "O:SYG:SYD:P(A;;KA;;;SY)"); sid != "S-1-5-18" && err == nil {
		t.Fatal("accepted another owner")
	}
	raw[0] ^= 0xff
	if err := k.SetBinaryValue("test", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(k, "test"); err == nil {
		t.Fatal("accepted corrupted checkpoint")
	}
}
func TestNonSystemCannotUseMachineStore(t *testing.T) {
	if RequireSystem() == nil {
		t.Skip("service account tested by native contract")
	}
	called := false
	if WithStore(context.Background(), func(registry.Key) error { called = true; return nil }) == nil || called {
		t.Fatal("non-System accessed signing store")
	}
}
