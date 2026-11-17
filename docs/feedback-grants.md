# Local human-feedback grants

The existing Unix Visor capability bridge has an optional `feedback_grants`
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
