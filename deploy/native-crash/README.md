# Disabled Linux container crash capture

The agent's existing `HYPERMESH_HOST_NATIVE_CRASH_ENABLED=1` opt-in connects
CPU, NVIDIA and ROCm container runners to a private installed helper. It still
requires configured machine reporting and current accepted Host Terms. No
configuration in this repository enables the switch or provisions collection.
Confidential guests do not use this path.

`Dockerfile.sdk` builds the native SDK, guarded handler, Host adapter and cleanup
helper from recorded source commits. Its final GHCR image contains runtime
binaries, shared libraries and license notices only. Sources, headers, static
archives and build tools remain in discarded build stages. Main CI publishes
moving `test-amd64` and `test-arm64` channels. No manual tag or release is needed.

`Dockerfile.worker` overlays those runtime files onto the caller's existing CPU,
NVIDIA or ROCm image through `WORKER_IMAGE`. It preserves the model binary,
accelerator ABI, entrypoint and configuration. Select the existing moving TEST
base for that variant; this overlay does not choose or certify a new base.
Linux glibc 2.35 or newer is required. Other libc/architecture combinations
remain unsupported and must keep native capture off.

The installed Host helper is
`/usr/local/libexec/hypermesh/crash-sdk/bin/host-container-cleanup`. It requires
the separately installed OS-managed Host retention service before preparing a
run. Private enrollment, the account-wide capture lock and ephemeral signing
key stay on Host. The workload sees only a read-only public control directory
and its writable raw database. No host PID namespace, host proc mount, Docker
socket, added capability or privileged container is used.

Host starts the container waiting for its public configuration, inspects its
full ID and init PID, then pins its live process, PID namespace and cgroup-v2
object. Only one handler process can use that session. Each write needs a fresh
signed response and current cleanup/Terms authority. Death, substitution,
timeout, restart and revocation refuse; no prior session is restored. An
unavailable preparation may start the original worker without capture only
before any container has started.

After the exact worker stops, Host revokes signing, reduces fixed crash fields,
deletes raw bytes, and only then submits sanitized metadata through the existing
exact-event registration path. Interrupted helper control closes and purges its
run; the OS cleanup service remains independently responsible for retention.
Automatic PR checks are unit and build contracts. Shared native scenarios belong
to the scheduled nightly adapter, not local or manually dispatched runs.
