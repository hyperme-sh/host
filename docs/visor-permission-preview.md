# Visor permission preview bridge

The existing private Visor capability bridge can provide a read-only permission
preview without exposing the host's machine credential. Its root-managed config
accepts optional `permission_preview` with `bot_id`, `assignment_id`, `session_id`
and `organization_id`. These select an existing owner-assigned interactive bot;
they do not create an assignment or grant. The bot must first be bound to the
same completed host registration through Plane's owner endpoint. Changed or
expired assignments return unavailable until configuration selects a current one.

The configured non-root Visor UID can read `/permission-context` for that
selection and submit `/permission-preview`. Context is explicitly
`configured_only`, not authenticated policy. Preview requests contain only
`project`, `template_version`, `template` and `action`; callers cannot replace the
host's tenant/device or configured assignment. The bridge obtains the existing
short-lived machine credential and sends it through stdin to the trusted
Conductor `permission-preview` command. It never returns the credential to Visor.

Conductor checks current Plane identity and asks AIuditor for the policy result;
AIuditor independently checks Plane context. The bridge verifies the returned
organization and assignment before forwarding the preview. An unavailable owner,
invalid config, expired identity or mismatched response gives a bounded error.
No root action, provider call or learned grant is enabled by this interface.

This is the host adapter for Visor #264. Native dialogs are provided by the
existing Linux companion; other clients can use their later owner adapters.
Unit contracts exercise the private handler with isolated credential and command
doubles. Shared journeys remain in scheduled CI.
