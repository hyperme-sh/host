# Host Go crash reporting

This optional configured path uses accepted Host Terms of Service, without an
additional consent prompt. Visor retains its separate consent rules. It requires
an already enrolled Host with current recorded Terms acceptance and an existing
machine signing identity. A fresh enrollment becomes eligible on the next start.

All settings are absent by default:

- `HYPERMESH_HOST_CRASH_ENABLED=1` enables the configured adapter.
- `HYPERMESH_HOST_CRASH_DSN=https://<project-key>@<operator-origin>/<project>`
  is the private ingest-only DSN. Keep it in the protected agent environment.
- `HYPERMESH_HOST_CRASH_REGISTRATION_URL=https://<operator-origin>/api/crash/register`
  must use the same HTTPS origin. Plane uses the existing control-plane URL.

Do not enable these settings until the destination and machine scope are
provisioned. Missing current Terms acceptance disables capture; invalid reporting
configuration logs a fixed warning and leaves normal Host operation available.
This source change does not enable reporting or digest billing.

The Linux/macOS service parent reexecutes the agent with a private runtime crash
pipe and keeps the service alive for one bounded report attempt after failure.
Go 1.23 or newer supplies `runtime/debug.SetCrashOutput`; no CGO dependency is
introduced. Unhandled goroutine panics and Go runtime fatal failures produce a
fixed `go_runtime_crash` event. Normal exits, returned errors and intentional
shutdown do not. SIGKILL, loss of power and failures before runtime initialization
cannot produce this report. Signal-terminated children return a conventional
128-plus-signal exit code; ordinary child exit codes are preserved.

Raw runtime text is drained through a fixed 4 KiB scratch buffer, cleared and
never persisted. The runtime's duplicate stderr output is discarded; ordinary
Go application logging retains its separate descriptor. No crash text, stacks,
paths, prompts or credentials are included in uploaded events. Because this
adapter writes no raw files, it does not start a raw cleanup service. Native
model-worker dump capture remains in Host #230 and requires that installed
service before capture, with the existing account-wide limits.

The parent rechecks current Terms and enrollment before sending. It obtains a
machine credential only from existing signing custody, sends it only to Plane,
and sends the broker only the exact-event grant. A verified tenant/device/project,
event/time/hash binding precedes one unchanged sanitized Sentry envelope upload.
Requests have a 20-second overall reporting deadline, no redirects, no inherited
proxy and no automatic retry. Failed reports are discarded, not queued.

Unit/contract checks exercise a disposable Go subprocess, fatal versus ordinary
exits, private-text exclusion, fixed JSON and fake HTTPS registration/upload
boundaries. Shared scenarios run only in scheduled CI. No installation, package
version change, tag or release is included.
