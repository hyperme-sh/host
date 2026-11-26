# Host recovery watchdog

Tracks [Host #292](https://github.com/hyperme-sh/host/issues/292). The watchdog
ships with standard Host installs and runs independently of the serving
agent. It accepts no remote commands. The current installer selects the
profile, service identity, release channel, and trusted signing keys. The
watchdog uses those local values for repair.

## Platform integration

| Platform | Service manager | Recovery scope |
| --- | --- | --- |
| Linux amd64 | systemd | The installed standard or isolated profile |
| Linux arm64 | systemd | The installed standard or isolated profile |
| macOS arm64 | launchd | The installed agent LaunchDaemon |

Use the existing signed checksum verification and atomic binary replacement
in `internal/update`. Keep the watchdog executable and service definition
outside the agent's replaceable path. Verify the profile's binary and state
paths against installer-owned configuration. The Linux adapter can reuse the
exact service mapping from [Host #291](https://github.com/hyperme-sh/host/pull/291).
The Darwin adapter must target the installed agent label and preserve the
separate WireGuard LaunchDaemon. Both adapters must work with the agent stopped.

## Repair contract

1. Check local process and installed binary health. A Plane outage, an owner
   pause, and a pending kernel reboot are separate conditions that leave the
   installation alone.
2. Establish that the selected profile has no live workload before changing
   its installation. Defer when work is active or ownership is unknown. Use a
   shared local lock with the updater so only one operation can replace the
   binary at a time.
3. Allow a bounded restart for a healthy binary. If local startup still fails
   or the binary is corrupt, restore a verified known-good artifact or obtain a
   verified artifact from the same release channel and architecture. Preserve
   enrollment, key files, owner settings and the model cache. Never generate a
   replacement identity in the repair path.
4. Persist enough state to resume after interruption and cap retries across
   restarts. Verify the actual running executable and local startup. A fresh
   heartbeat confirms recovery from Plane's perspective. If Plane is
   unavailable, retain the local result without triggering another reinstall.
5. Surface a specific terminal reason for lost enrollment, storage failure, or
   exhausted retries. Route it through the existing owner status path when
   available. Use Plane's last-seen alert when the host cannot report. Disk
   replacement guidance requires positive storage diagnostics.

The first implementation should exercise these decisions with fake service
managers and signed fixtures. Cover both Linux architectures and Darwin,
wrong-channel and wrong-profile artifacts, interrupted replacement, ownership
uncertainty, failure backoff, and state preservation. Then wire the watchdog
service into each installer and qualify the platform contracts through CI.

## Installed watchdog

The standard Linux installer registers `hypermesh-recovery.timer` and its
oneshot service. The timer checks every five minutes after activation. The
macOS owner registration installer loads a separate
`com.fyberlabs.hypermesh-recovery` LaunchDaemon with the same interval. The
watchdog uses a signed copy of the release installer in
`/usr/local/libexec/hypermesh-recovery`.

On macOS, the owner registration command needs the verified bootstrap
metadata and public key beside the installer. The recovery LaunchDaemon
needs a root-managed GnuPG installation. Its search path accepts a
root-managed MacGPG2 package or system GnuPG and excludes Homebrew.

Terminal recovery notices appear in the local owner console and service
logs. To read the notice while the agent is down, run
`sudo /usr/local/libexec/hypermesh-recovery recovery-watchdog status`.
