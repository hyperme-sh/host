//go:build linux || darwin

package visorbridge

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKernelPeerIdentity(t *testing.T) {
	path := filepath.Join(realTempDir(t), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	uid, err := peerUID(server)
	if err != nil || uid != uint32(os.Geteuid()) {
		t.Fatal(uid, err)
	}
}
func TestOwnedExecutableAndConfigPaths(t *testing.T) {
	dir := realTempDir(t)
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "conductor")
	os.WriteFile(path, []byte("fixture"), 0700)
	if trustedPath(path, true) != nil {
		t.Fatal("owned executable refused")
	}
	os.Chmod(path, 0777)
	if trustedPath(path, true) == nil {
		t.Fatal("writable executable allowed")
	}
	os.Chmod(path, 0700)
	alias := filepath.Join(dir, "alias")
	os.Symlink(path, alias)
	if trustedPath(alias, true) == nil {
		t.Fatal("symlink executable allowed")
	}
}

func TestListenerDropsWrongKernelUIDBeforeHTTP(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is the trusted control peer")
	}
	path := filepath.Join(realTempDir(t), "refuse.sock")
	unix, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener := &peerListener{UnixListener: unix, uid: uint32(os.Geteuid()) + 1, slots: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() { _, err := listener.Accept(); done <- err }()
	client, err := net.Dial("unix", path)
	if err != nil {
		unix.Close()
		t.Fatal(err)
	}
	defer client.Close()
	client.SetReadDeadline(time.Now().Add(time.Second))
	var buffer [1]byte
	if _, err = client.Read(buffer[:]); err != io.EOF {
		t.Fatal("wrong peer not closed", err)
	}
	unix.Close()
	if <-done == nil {
		t.Fatal("unauthorized connection accepted")
	}
}

// macOS temporary paths may contain the fixed /var alias. Tests use its real
// directory; production paths are never silently canonicalized.
func realTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "vfb-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	path, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFeedbackConfigLoadRefusesUnsafePaths(t *testing.T) {
	dir := realTempDir(t)
	path := filepath.Join(dir, "feedback.json")
	raw := []byte(`{"schema":1,"feedback_only":true,"feedback_grants":true,"client_uid":501}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(path); err != nil || !c.FeedbackOnly || !c.FeedbackGrants {
		t.Fatal("owned config refused", err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(alias); err == nil {
		t.Fatal("symlink allowed")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("writable config allowed")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("writable parent allowed")
	}
}
