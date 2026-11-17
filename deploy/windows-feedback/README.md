# Windows feedback grant broker

This dedicated LocalSystem service serves only `POST /feedback-grant` on
`\\.\pipe\hypermesh-feedback-grant-v1`. The SCM name is `HypermeshFeedbackGrant`.
The request is `{"version":1,"human_reports_opt_in":true}`; response is the existing
version/grant/expires_in envelope, at most 4096 bytes. Requests are bounded to 256
bytes, connections to 16, and upstream grant operations to eight with 12-second
deadlines. There are no report, crash, enrollment or arbitrary signing routes.

The configured SID must be an individual local/domain account. A private pipe ACL
allows only that user and LocalSystem; it denies client server-instance creation.
Every request verifies the client's token user and medium-or-higher integrity,
rejecting restricted or anonymous clients. Visor must independently verify the
SCM LocalSystem service process and pipe owner before sending.

The service uses the existing LocalSystem machine identity store. An existing
matching enrollment is required; it does not enroll, retire or copy credentials.
The general credential goes only to the configured HTTPS Plane origin. Plane
feedback grants and intake membership must already be configured for an enabled
service to return a grant. Those changes are outside this disabled implementation.

Build `./cmd/hypermesh-feedback-service` for Windows. `install.ps1` accepts an
executable and a version-1 configuration with `enabled: false`; it installs into
`Program Files/HypermeshFeedbackService` with protected Administrator/System-only
ACLs and creates a disabled LocalSystem service. It refuses an existing directory
or service, never starts the service, and does not change the crash service.
Review actual tenant/device/SID configuration before any separately authorized
activation. The example contains placeholders and cannot be used as real setup.

Native Windows unit contracts run in CI for pipe caller identity, wrong SID,
anonymous clients, ACLs, hardlinks, disabled service refusal and HTTP dispatch.
