//go:build windows

package windowsfeedback

import (
	"context"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"
)

func TestPipeDescriptorDoesNotGrantServerCreation(t *testing.T) {
	if _, err := pipeDescriptor("S-1-5-18"); err == nil {
		t.Fatal("service account allowed as client")
	}
	if _, err := pipeDescriptor("S-1-5-32-544"); err == nil {
		t.Fatal("group allowed")
	}
	if _, err := pipeDescriptor("S-1-5-21-1-2-3-1001)(A;;GA;;;WD)"); err == nil {
		t.Fatal("descriptor injection")
	}
	sd, err := pipeDescriptor("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := windows.SecurityDescriptorFromString(sd); err != nil {
		t.Fatal(err)
	}
	if uint32(0x12019b)&windows.FILE_APPEND_DATA != 0 {
		t.Fatal("client can create server instances")
	}
}
func TestNamedPipeClientContextAndWrongSID(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for _, tc := range []struct {
		name    string
		level   winio.PipeImpLevel
		allowed bool
	}{
		{"identification", winio.PipeImpLevelIdentification, true}, {"anonymous", winio.PipeImpLevelAnonymous, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf(`\\.\pipe\hypermesh-feedback-unit-%d`, time.Now().UnixNano())
			l, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + sid + ")"})
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			result := make(chan bool, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					result <- false
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				var raw [1]byte
				if _, err = io.ReadFull(c, raw[:]); err != nil {
					result <- false
					return
				}
				h := windows.Handle(c.(interface{ Fd() uintptr }).Fd())
				result <- (clientAllowed(h, sid) == tc.allowed) && !clientAllowed(h, "S-1-5-21-1-2-3-9999")
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := winio.DialPipeAccessImpLevel(ctx, path, 0x12019b, tc.level)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err = c.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			select {
			case ok := <-result:
				if !ok {
					t.Fatal("pipe context validation failed")
				}
			case <-ctx.Done():
				t.Fatal("pipe test timeout")
			}
		})
	}
}
func TestDisabledServiceRefusesBeforeCredentialAccess(t *testing.T) {
	if serve(context.Background(), Config{Version: 1}) == nil {
		t.Fatal("disabled service accepted")
	}
}

func TestInstalledFilesRequirePrivateACLAndSingleLink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "installed")
	descriptor, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	dirName, _ := windows.UTF16PtrFromString(dir)
	if err := windows.CreateDirectory(dirName, &sa); err != nil {
		t.Fatal(err)
	}
	parent, err := installedFile(dir, true)
	if err != nil {
		t.Fatal("private directory refused", err)
	}
	parent.Close()
	path := filepath.Join(dir, "config.json")
	name, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(h)
	f, err := installedFile(path, false)
	if err != nil {
		t.Fatal("private file refused", err)
	}
	f.Close()
	link := filepath.Join(dir, "second.json")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if f, err := installedFile(path, false); err == nil {
		f.Close()
		t.Fatal("hardlinked config accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	openSD, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := openSD.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if f, err := installedFile(path, false); err == nil {
		f.Close()
		t.Fatal("public config accepted")
	}
}
