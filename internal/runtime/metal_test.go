package runtime

import (
	"context"
	"strings"
	"syscall"
	"testing"
)

func TestMetalStartArgsNoCUDA(t *testing.T) {
	args := MetalStartArgs(Spec{LeaseID: "lease-m", HostPort: "8080"}, "llama-server")
	joined := strings.Join(args, " ")
	if args[0] != "llama-server" || !contains(args, "--host") || !contains(args, "127.0.0.1") {
		t.Fatalf("llama-server listen: %v", args)
	}
	if !contains(args, "--port") || !contains(args, "8080") {
		t.Fatalf("port: %v", args)
	}
	for _, a := range args {
		al := strings.ToLower(a)
		if strings.Contains(al, "cuda") || strings.Contains(al, "nvidia") ||
			a == "--gpus" || strings.HasPrefix(a, "--gpus=") {
			t.Fatalf("must not invent CUDA on Mac: %v", args)
		}
	}
	for _, leak := range []string{"tok/s", "TOPS", "tokens/sec", "gfx1036"} {
		if strings.Contains(joined, leak) {
			t.Fatalf("unexpected %s: %v", leak, args)
		}
	}
}

func TestMetalStartMock(t *testing.T) {
	var seen [][]string
	m := &Metal{
		Bin: "llama-server",
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			seen = append(seen, append([]string{name}, args...))
			if name == "/bin/ps" {
				return []byte("/usr/local/bin/llama-server\n"), nil
			}
			return []byte("42\n"), nil
		},
	}
	got, err := m.Start(context.Background(), Spec{LeaseID: "lease-m", ImageDigest: testRef})
	if err != nil {
		t.Fatal(err)
	}
	if got.Backend != BackendLlamaCppCPU || got.ContainerID != "42" {
		t.Fatalf("handle %+v", got)
	}
	if len(seen) != 1 || seen[0][0] != "llama-server" {
		t.Fatalf("calls %v", seen)
	}
	if err := m.Stop(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || seen[2][0] != "/bin/kill" || seen[2][1] != "-KILL" {
		t.Fatalf("stop %v", seen)
	}
}

func TestMetalStartEmptyDigest(t *testing.T) {
	m := &Metal{Run: func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("must not run without digest")
		return nil, nil
	}}
	_, err := m.Start(context.Background(), Spec{LeaseID: "l"})
	if err != ErrNoImage {
		t.Fatalf("got %v", err)
	}
}

func TestMetalDefaultImageStubsLlamaCppCPU(t *testing.T) {
	if MetalImageEnabled() || CPUImageEnabled() {
		t.Skip("darwin image: see metal_darwin_test.go")
	}
	path, reason := ResolveBackend(BackendLlamaCppCPU)
	want := "This image does not run llama-cpp-cpu."
	if path != StubFail || reason != want {
		t.Fatalf("Jetson image must stub llama-cpp-cpu: path=%v reason=%q", path, reason)
	}
	path, reason = ResolveBackend("llama-cpp-metal")
	if path != StubFail || reason != "This image does not run llama-cpp-metal." {
		t.Fatalf("llama-cpp-metal is not in the enum: path=%v reason=%q", path, reason)
	}
}

func TestMetalStopToleratesStaleProcess(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		err           error
	}{
		{name: "already exited", err: syscall.ESRCH},
		{name: "reused process ID", command: "/usr/bin/unrelated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Metal{Run: func(_ context.Context, name string, _ ...string) ([]byte, error) {
				if name != "/bin/ps" {
					t.Fatalf("unexpected signal for stale process: %s", name)
				}
				return []byte(tc.command), tc.err
			}}
			if err := m.Stop(context.Background(), &Handle{ContainerID: "42"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
