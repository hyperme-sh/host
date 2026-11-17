//go:build windows

package windowscrash

import (
	"context"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"io"
	"testing"
	"time"
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
	path := fmt.Sprintf(`\\.\pipe\hypermesh-crash-unit-%d`, time.Now().UnixNano())
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
		result <- clientAllowed(h, sid) && !clientAllowed(h, "S-1-5-21-1-2-3-9999")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := winio.DialPipeContext(ctx, path)
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
}
func TestDisabledServiceRefusesBeforeEnrollment(t *testing.T) {
	if serve(context.Background(), Config{Version: 1}) == nil {
		t.Fatal("disabled service accepted")
	}
}
