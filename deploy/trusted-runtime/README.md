# Trusted CPU token meter implementation

Tracking: [Host #216](https://github.com/hyperme-sh/hypermesh-host/issues/216).
Owner prerequisites: [Plane #155](https://github.com/hyperme-sh/hypermesh-plane/pull/155),
[#158](https://github.com/hyperme-sh/hypermesh-plane/pull/158), and
[#160](https://github.com/hyperme-sh/hypermesh-plane/pull/160) supply grant timing,
fresh key-bound channels, and explicit trusted Host dispatch.

This profile is opt-in and default-off. Host setup does not install a guest
bundle, and the ordinary CPU runtime does not select this profile.
The ordinary Docker runtime cannot satisfy the confidential execution boundary.

## Counter and wire contract

Policy `processed-input-accepted-output-v1` bills processed input plus accepted
output. Processed input excludes cache hits. Hidden output is a subset of
accepted output, never an extra charge. Cache hits and rejected speculative
proposals are recorded without charging. Prompt counts remain record-only.
Existing per-1,000-token pricing and failed-token refunds are unchanged.

The bounded initial engine uses the pinned llama.cpp commit in `engine/source.json`.
It has fresh request contexts, greedy decoding, at most 2048 input tokens and
128 accepted output tokens. Cache reuse and speculative decoding are disabled,
so their actual counters are zero. Model and tokenizer digests both identify the
same GGUF file for this profile. Templates use llama.cpp's built-in template
support, not arbitrary Jinja execution. Control, end, and empty output tokens
are hidden; all other generated pieces, including reasoning text, are emitted
and counted as accepted output. No accelerator backend is supported.

Input counts advance after successful decode, in chunks of at most 32 tokens.
Accepted output advances once per selected token. Each cumulative count is
signed and journaled, then anchored at Plane before the next permitted step or
output delivery. A failed decode, lost anchor reply, or expired grant leaves an
uncertain request disputed. A bounded step can finish after disconnection;
this implementation does not promise instantaneous stopping.

The Go package verifies Plane's signed response domain, complete request hash,
tenant, lease, Gateway, immutable budgets, and grant identity. A fresh start
nonce prevents substitution of a prior first-start reply. The grant interval is
anchored to the protected clock sample before the initial send, subtracting one
second for timestamp quantization and the qualified rate allowance. Replayed
starts never authorize work; late renewals cannot resurrect an expired grant.

The count-only journal is partitioned by runtime key and request, so completed
requests do not exhaust a shared lifetime quota when settled history is retired.
The guest bounds retained history to 256 files and 64 MiB, reserving room for
atomic replacement before each request. Host reserves that allowance within
a global 2048-file/256-MiB history budget before launching a lease. Quota
exhaustion refuses new work while keeping existing status readable. Each
bounded partition uses
atomic replacement, file and directory sync, strict
JSON parsing, signatures, hash continuity, and monotonically increasing counts.
After reopening, it serves existing records read-only and never resumes work.
A local terminal record still needs its matching Plane anchor for settlement.
Missing terminal records do not imply zero work. No private key, prompt, output,
token ID, or prompt hash is stored in the journal.

## Guest, channel and Host contract

The static `hypermesh-meter-guest` binary is PID 1 in a minimal initrd. It
requires a built-in SNP/Secure TSC kernel and rejects modules, suspend, swap,
user namespaces and debug interfaces. There is no shell, dynamic loader,
provider-supplied trust root or key export. The counted worker runs as UID 65534
in separate network, PID, IPC and UTS namespaces with no new privileges.
Only private pipes and sealed model/template/binary file descriptors reach it.
The guest copies and hashes model data into sealed memory before accepting work;
changes to the provider's exported model cannot alter those bytes.

TLS 1.3 terminates in the guest using the ephemeral attested Ed25519 key.
`POST /channels/challenge` accepts a Gateway key; `/channels/authorize` consumes
the fresh Plane-signed key binding once. The resulting short-lived channel
requires proof of that same TLS client key and the channel token. Certificate
wall-clock dates do not authorize it. Authenticated `POST /quote`, `/status`
and `/execute` bind the complete lease and request. Execution relays owner
operations only over HTTPS pinned to the authorized Gateway key. Admission is
separate from the durable start decision and short protected-clock grants.

Status returns count-only signed history. Execute accepts bounded messages and
limits, buffers output transiently, and returns it only after the terminal
count is anchored. The journal never resumes a reopened request. A new guest
can serve an earlier public key's signed records, but cannot renew that session.

Authenticated `POST /retire` accepts `batch_id`, `runtime_key`, `operation`
(`recover` or `cancel`) and the signed Plane owner `proof`. Retirement requires
a matching recovered terminal hash/counters, or a matching owner no-start
cancellation for an entry that never started. It never removes ambiguous or
unsettled work. Gateway must commit its recovery first, then retire local copies;
Plane remains the durable archive for immutable terminal replay. Host status
can report missing after explicit retirement, so recovery must use owner history.
Duplicate retirement is harmless. Missing proofs cannot bypass storage quotas.

Host dispatch requires `runtime` and `backend` equal to `sev-snp-cpu`, the full
`trusted_meter` binding, and `HYPERMESH_TRUSTED_METER_BUNDLE` pointing to a
configured bundle directory. Missing configuration, changed scope, private
model sources, unsupported platforms or failed launch refuse the job. There
is no ordinary runtime fallback. Host forwards opaque TCP through the existing
tunnel; a listening socket is not attestation. Gateway must verify the quote
and owner authority before sending inference. Shutdown stops the dedicated
systemd unit (or confirms an already-collected unit is inactive with no PIDs) and removes staged boot/input files while retaining count history.

## Preparing a profile

Build the static Go init with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
-trimpath -o meter-init ./cmd/hypermesh-meter-guest`. Build the CPU engine against
the exact source revision in `engine/source.json`; CMake disables dynamic
backends and emits a static PIE. `build-initrd.py --help` describes the explicit
owner public key, model digest, fixed template and qualified clock allowance.
The deterministic archive builder rejects dynamically linked binaries. Its
artifact manifest deliberately has no approved measurement.

Infra supplies `firmware.fd`, `kernel`, `initrd.cpio` and `bundle.json`. The bundle
has schema 1, the generated `profile`, independently approved `measurement`,
SHA-256 fields `firmware_sha256`, `kernel_sha256`, `initrd_sha256`, plus
`cbitpos`, `reduced_phys_bits`, `memory_mib` and `tsc_frequency_khz`. The selected
profile must cover the exact kernel, initrd, command line, one-vCPU configuration
and Secure TSC rate. `kernel.go` defines required and forbidden kernel options;
all required drivers are built in. Memory includes both the private model copy
and CPU allocation, with 2 GiB additional allowance. Kernel/firmware support and
QEMU Secure TSC properties are mandatory; failed startup never downgrades them.

The Host launch fixes SNP policy to `0x30000` (no debug or migration), uses
stateless firmware with `kernel-hashes=on`, disables monitor/serial access,
and supplies `GuestCommandLine` from `bundle.go` unchanged. QEMU needs the
`secure-tsc` and `tsc-frequency` properties documented in its 11.1 interface.
These artifact hashes describe the confidential workload, not peer service
version requirements or service deployment pins.

Do not persist a guest private key merely to serve historical final records.
Recovery can return the original signed records and public key for verification
against Plane's stored session and anchor. A new guest session must not renew or
execute an old request.

Independent verifier configuration, approved measurements, vendor policy, and
scheduled qualification are tracked in
[Infra #1638](https://github.com/FyberLabs/infra/issues/1638). That work must independently verify the workload measurement, vendor chain,
chip/host assignment, Secure TSC pause/rollback behavior and clock rate. Source
checks cannot establish platform qualification. Gateway #70 and
#69 remain downstream. Digest billing stays disabled.

## Unit and contract validation

`go test -race ./internal/trustedmeter` checks the wire fixture produced by
Plane's Python signer, owner grants, replay/expiry/rollback handling, budgets,
journal restart, key-bound channels, sealed files, launch staging, shutdown,
and file digests. Agent unit checks cover default-off dispatch and retry scope. `counter-contract` checks the isolated C++
count hook and failed decode behavior. The CI engine job builds the pinned CPU
source without downloading a model or running inference.

## Platform references

The clock checks use Linux's [SNP Secure TSC status bit](https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/msr-index.h)
and the measured kernel's `CLOCK_MONOTONIC_RAW` TSC source. The initial profile
must disable suspend, clock replacement, migration, debug access and swap.
The issuer must qualify its rate bound; the constructor does not infer it.

Quote collection uses [go-sev-guest v0.15.0](https://github.com/google/go-sev-guest/tree/v0.15.0).
Its [key derivation limitations](https://github.com/google/go-sev-guest/blob/v0.15.0/LIMITATIONS.md)
explain why a generic firmware measurement does not identify a workload. This
implementation does not derive or seal a key under a generic VM measurement.

Boot settings follow the [QEMU AMD memory encryption contract](https://www.qemu.org/docs/master/system/i386/amd-memory-encryption.html)
and [Secure TSC guest properties](https://github.com/qemu/qemu/blob/master/qapi/qom.json).
