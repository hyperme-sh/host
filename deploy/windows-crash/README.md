# Windows crash registration service

Build the dedicated Windows executable from `cmd/hypermesh-crash-service`.
It runs only through Service Control Manager as `HypermeshCrashRegistration`,
under LocalSystem. It does not require the Windows model-host executable.
The existing raw-dump cleanup service keeps its user account and storage.

An administrator prepares a private configuration from `config.example.json`.
Use the existing owner-approved enrollment's tenant, device, request ID and
one-time enrollment secret (`enrollment_secret`). Do not mint manual JWTs,
copy a human session, or give this secret to Visor or the crash broker.
Set `client_sid` to the single approved Windows user's account SID. The Plane
and registration URLs must be operator-selected HTTPS endpoints; the latter
ends in `/api/crash/register`. The registry journal permanently binds the
signer to the enrolled device and network. Wrong bindings fail closed.

Run `install.ps1 -Executable <built-exe> -Config <private-config>` from an
administrator shell to prepare a fresh installation. It creates a protected
Program Files directory and private files, and registers a **disabled** service.
It refuses to overwrite an existing installation. Keep the source configuration
private too. There is no automatic activation, tag or release in this slice.

The source configuration has `enabled: false`. Enabling registration and starting
the installed service are separate operator actions after its required owning
configuration is ready; they are not performed by these changes. The service
first checkpoints an Ed25519 signing key, then binds it through the existing
Plane protocol. After binding, remove `enrollment_secret` from the private
configuration; the same installed identity renews without it. A failed or lost
bind response can retry with the same checkpoint and enrollment secret.

Signing state is DPAPI-protected as LocalSystem in a protected LocalSystem-only
HKLM registry key. A private cross-process mutex serializes writes and rotation;
registry writes are flushed before use. To retire an enrollment, an administrator
sets `enabled: false` and `retire_enrollment: true` in the protected configuration
and explicitly starts the service for that operation. It archives the current
signing checkpoint and exits without opening a pipe. Retired device IDs cannot
be rebound. Never delete the journal to bypass retirement. A new enrollment
uses a fresh owner-approved device ID and request ID, with retirement mode cleared.

The local endpoint is `\\.\pipe\hypermesh-crash-registration-v1`. It rejects
remote clients, reserves the first pipe instance, and grants the allowed user
specific data rights without permission to create server instances. The service
checks the connected client's SID and token after reading a bounded request,
then restores its own identity before accessing credentials. Restricted and
low-integrity client tokens are refused. Only `POST /crash-register` is exposed.
The body contains the approved event ID, original UTC time and JSON hash; raw
dumps and arbitrary file paths are never accepted. The general machine token
goes only to Plane. Only the 60-second exact-event crash grant reaches the broker.
Visor must verify the installed service identity before sending and validate all
returned event/owner/project bindings before its unchanged sanitized upload.

Windows unit and contract tests run in disposable CI. The signing checkpoint
contract uses a temporary CI task under LocalSystem with fake HTTPS services.
It requires an absent registry store and removes its fixture afterward. Do not
run this fixture on an installed machine. Digest activation remains disabled.
