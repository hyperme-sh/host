package agent

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/internal/pathb"
	"github.com/FyberLabs/hypermesh-host/internal/runtime"
	"github.com/FyberLabs/hypermesh-host/internal/trustedmeter"
)

func (a *Agent) trustedStarter() runtime.Starter {
	if a.trusted != nil {
		return a.trusted
	}
	return runtime.NewSNP(a.cfg.TrustedMeterBundle, a.cfg.StateDir)
}
func (a *Agent) leaseStartTrusted(ctx context.Context, job api.Job) pathb.Result {
	refused := pathb.Result{Reason: "trusted CPU runtime unavailable"}
	b := job.TrustedMeter
	if !runtime.SNPEnabled() || a.cfg.TrustedMeterBundle == "" || b == nil || b.Validate() != nil || b.TenantID != a.cfg.TenantID || b.LeaseID != job.LeaseID || b.DeviceID != job.DeviceID || job.Runtime != runtime.BackendSNP || job.Backend != runtime.BackendSNP || strings.HasPrefix(job.SourceRef, privateModelPrefix) || job.ModelConfiguration != nil {
		return refused
	}
	if a.effectiveSell().SellState == api.SellPaused || runtime.TunnelBindHost(a.currentBindIP()) == "" {
		return refused
	}
	bindingHash, err := trustedmeter.Hash(*b)
	if err != nil {
		return refused
	}
	if existing := a.localLease(); existing != nil {
		if existing.LeaseID != job.LeaseID || existing.Backend != runtime.BackendSNP || existing.TrustedMeterBindingSHA256 != bindingHash {
			return refused
		}
		if existing.Serving() {
			if existing.FileHash != job.FileHash || existing.CatalogID != job.CatalogID {
				return refused
			}
			if a.leaseReady != nil {
				err = a.leaseReady(ctx, existing)
			} else {
				err = a.waitTrustedGuest(ctx, existing)
			}
			if err != nil {
				return refused
			}
			if a.leaseReady == nil && a.ensureTrustedForwarder(existing) != nil {
				return refused
			}
			return pathb.Result{Passed: true, ImageHash: existing.FileHash, Reason: "lease_start"}
		}
		if result, ok := a.recoverUnreadyLease(existing); !ok {
			return result
		}
	}
	if job.SourceRef != "" {
		if job.SizeBytes <= 0 || a.checkDemandFit(ctx, job.SizeBytes, runtime.BackendLlamaCppCPU) != nil {
			return refused
		}
		if result := a.labPull(ctx, artifactPullJob(job)); !result.Passed {
			return result
		}
	}
	model, _, _, failure := a.leaseModelPath(job)
	if failure.Reason != "" {
		return failure
	}
	if a.authorizePrivateCacheFile(ctx, job, model) != nil {
		return refused
	}
	bundle, err := trustedmeter.LoadBundle(a.cfg.TrustedMeterBundle, *b)
	if err != nil || a.checkDemandFit(ctx, int64(bundle.MemoryMiB)<<20, runtime.BackendLlamaCppCPU) != nil {
		return refused
	}
	hash, err := runtime.HashGGUFFile(model)
	if err != nil || strings.TrimPrefix(hash, "sha256:") != b.ModelSHA256 || strings.TrimPrefix(job.FileHash, "sha256:") != b.ModelSHA256 {
		return refused
	}
	handle, err := a.trustedStarter().Start(ctx, runtime.Spec{LeaseID: job.LeaseID, CatalogID: job.CatalogID, Runtime: job.Runtime, Backend: job.Backend, GGUFPath: model, TrustedMeter: b})
	if err != nil {
		if handle != nil {
			a.recordStarting(handle)
			a.abandonStarted(ctx, handle)
		}
		return refused
	}
	a.recordStarting(handle)
	if a.leaseReady != nil {
		err = a.leaseReady(ctx, handle)
	} else {
		err = a.waitTrustedGuest(ctx, handle)
	}
	if err != nil {
		a.abandonStarted(ctx, handle)
		return refused
	}
	if !a.markServing(handle) {
		a.stopLeaseForwarder()
		return refused
	}
	if a.leaseReady == nil && a.ensureTrustedForwarder(handle) != nil {
		a.abandonStarted(ctx, handle)
		return refused
	}
	a.clearPendingModel(job.CatalogID)
	a.touchModelUse(hash)
	return pathb.Result{Passed: true, ImageHash: hash, Reason: "lease_start"}
}
func (a *Agent) waitTrustedGuest(ctx context.Context, h *runtime.Handle) error {
	if !runtime.ValidTrustedDial(h.TrustedMeterDial) {
		return runtime.ErrTrustedRuntime
	}
	bounded, cancel := context.WithTimeout(ctx, a.readyTimeout())
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(bounded, "tcp", h.TrustedMeterDial)
		if err == nil {
			connection.Close()
			return nil
		}
		select {
		case <-bounded.Done():
			return runtime.ErrTrustedRuntime
		case <-ticker.C:
		}
	}
}

// This is an opaque TCP forwarder: TLS ends inside the measured guest.
// Listening is not attestation; Gateway independently verifies the runtime.
func (a *Agent) ensureTrustedForwarder(h *runtime.Handle) error {
	if h == nil || !h.Serving() || !runtime.ValidTrustedDial(h.TrustedMeterDial) {
		return runtime.ErrTrustedRuntime
	}
	listen := a.leaseListenAddr()
	if listen == "" {
		return runtime.ErrTrustedRuntime
	}
	a.fwdMu.Lock()
	defer a.fwdMu.Unlock()
	current := a.currentLease()
	if current == nil || !current.Serving() || current.LeaseID != h.LeaseID || current.ContainerID != h.ContainerID || current.TrustedMeterBindingSHA256 != h.TrustedMeterBindingSHA256 {
		return runtime.ErrTrustedRuntime
	}
	if a.forwarderCurrentLocked(listen, h.TrustedMeterDial) {
		return nil
	}
	if err := a.startLeaseForwarderLocked(listen, h.TrustedMeterDial); err != nil {
		return err
	}
	current.PublishAddr = listen
	return nil
}
