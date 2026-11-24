package agent

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/internal/runtime"
)

func TestPauseCutsOffIssuedLeaseTraffic(t *testing.T) {
	for _, name := range []string{"ordinary", "self-use"} {
		t.Run(name, func(t *testing.T) {
			a := newOwnerTestAgent(t)
			backend, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			go func() {
				conn, err := backend.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
			a.fwd, err = startLeaseForwarderLimit("127.0.0.1:0", backend.Addr().String(), 4, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			defer a.stopLeaseForwarder()

			// Both ticket types reach the same Host listener after Gateway
			// authorization. The Host receives no payer or self-use flag.
			docker := &scriptedDocker{}
			a.runtime = &runtime.NVIDIA{Run: docker.run}
			handle := &runtime.Handle{LeaseID: name, ContainerID: "test-container"}
			a.setLease(handle)
			addr := a.fwd.ln.Addr().String()
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 1)
			if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "x" {
				t.Fatalf("pre-pause traffic failed: %q, %v", reply, err)
			}

			out := a.runJob(context.Background(), api.Job{Kind: api.KindSellPause, DeviceID: testDevice})
			if !out.Passed || out.SellState != api.SellPaused {
				t.Fatalf("pause failed: %+v", out)
			}
			if _, err := conn.Read(reply); err != io.EOF {
				t.Fatalf("pause did not close the in-flight connection: %v", err)
			}
			a.ensureLeaseForwarder(context.Background())
			if next, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
				next.Close()
				t.Fatal("paused listener accepted a new connection")
			}
			if a.localLease() != nil || !docker.saw("stop") || !docker.saw("rm") {
				t.Fatal("paused host retained a running workload")
			}
		})
	}
}
