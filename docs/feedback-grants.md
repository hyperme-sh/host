# Local human-feedback grants

The existing Linux Visor capability bridge has an optional `feedback_grants`
boolean, default false, in its protected configuration. When enabled, only the
configured non-root `client_uid` may POST `/feedback-grant` with
`{"version":1,"human_reports_opt_in":true}`. Root's separate review interface
and the Windows crash-only service do not expose this route.

Host generates the request UUID and uses the configured tenant/device and current
machine credential for Plane's fixed `/api/v1/hypermesh/agent/feedback/grant`
route. The general credential stays inside Host and is sent only to the configured
HTTPS Plane origin. Proxies and redirects are disabled, bodies/responses are
bounded, and the existing concurrency limit plus a 12-second timeout apply.
Upstream errors are never returned verbatim.

Host returns only a short-lived `hm_feedback_` grant after checking its fixed
scope, tenant, device, request UUID and expiry against the authenticated Plane
response. Intake independently verifies the Ed25519 signature. The local opt-in
flag is an explicit caller assertion, not proof of a human gesture or server
consent. Intake still requires current membership, consent revision and per-report
confirmation. Grants may be reused for their remaining lifetime, at most 60
seconds; they cannot review/export/administer intake.

No configuration is enabled here. Visor caller/UI composition, report transport,
OIDC phone support and Windows feedback transport remain separate. This route
performs no report submission, file collection, persistence or credential logging.

## macOS feedback-only broker

The existing `hypermesh-host visor bridge --config <path>` command also supports
an explicitly configured feedback-only mode on macOS (and Linux). Both
`feedback_only` and `feedback_grants` must be true. Its configuration contains
only schema 1, a nonzero `client_uid`, an absolute `socket` path, an absolute
`identity` path, the HTTPS Plane `base`, and canonical `tenant` and `device` IDs.
Capability, Conductor, crash and controller settings are rejected in this mode.

Run the broker as root with root-owned configuration and a pre-existing root-owned
socket directory whose ancestors cannot be changed by other users. Paths must be
canonical without symlink components; on macOS use `/private/var/...` rather than
the `/var` alias. The existing socket is never replaced. The configured Visor UID
is authenticated with macOS `LOCAL_PEERCRED` (Linux uses `SO_PEERCRED`), before HTTP
handling. Only that non-root UID may POST `/feedback-grant`; root and unrelated
routes are refused. No capability runner, reviewer or signer is installed.

This change supplies no launch service or enabled configuration. The macOS general
capability/controller bridge remains unavailable. Windows still needs its own
feedback-only authenticated pipe transport; the crash-only service is unchanged.
