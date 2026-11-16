# Local host health authorization

`GET /v0/health_authorization` is served only on the existing private `owner.sock`
and requires its existing owner credential. It is for the headless host health
agent, not Visor opt-in, and opens no listener or new credential store.

Every request checks the enrolled device's recorded acceptance against the
bundled terms version and hash, including a valid non-future acceptance time.
It then calls the existing machine-authenticated `GET /agent/tunnel` route, which
checks current device authorization before either a 200 or 204 response. No
assigned tunnel is required. A failed request, including incomplete tunnel setup,
is unavailable rather than authority. The device record is checked again after
the request to refuse enrollment or agreement changes during the check.

A 200 response contains `version: 1`, `policy: host-agreement`, `device_id`,
`tenant_id`, `terms_version`, `terms_sha256`, and `checked_at`. It contains no
machine credential, owner token, tunnel details or health data. It is a local
point-in-time result, not a bearer credential or persisted grant. Consumers must
check before collection and again before upload, bind both results to the same
machine and terms, and discard samples when either check fails. Do not cache it
or use it to authorize a Visor installation. No interactive consent is requested.

Missing owner credentials return 401; invalid local enrollment/agreement or a
concurrent change returns 403; upstream refusal/unavailability returns 503;
non-GET requests return 405. Replies use `Cache-Control: no-store`. Errors carry
no upstream response bodies. Selling posture is neither read nor changed.

This supplies the host boundary for Visor #217. Shared health-agent consumption,
headless packaging and the collector transport are separate remaining work;
Infra #1435 owns the collector contract. Existing host heartbeat monitoring is
unchanged. Contract tests use a fixture service, not a deployed host or collector.
