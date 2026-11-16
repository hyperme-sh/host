# Assigned editor prompt bridge

The root-owned bridge configuration may include `machine_prompt` with the existing
`bot_id`, `assignment_id`, `session_id`, `organization_id`, plus `workspace`,
`socket` (the root-private Conductor socket), `class`, `destination` and
`max_output_tokens`. This selects an already enrolled owner host and assigned
interactive bot. It does not create consent or assignment. `base` and the
Conductor executable remain protected bridge configuration.

The configured non-root UID can request `/machine-context`. The bridge gets a
current Plane fact through Conductor and returns only identity and configured
routing metadata. Visor independently checks its local active session and project.
The signed-in owner then commits the exact prompt digest to Plane's owner-prompt
endpoint. Only afterward does Visor submit those bytes to `/machine-prompt`.
The bridge refuses another identity, route or output limit and injects its private
machine credential over stdin. Conductor verifies the owner task before AIuditor
and provider dispatch. No owner token, machine credential or private key reaches
the editor. Owner authorization cannot be replaced with machine context alone.

Requests are bounded to thirty seconds. Disconnect cancels the child request;
unknown outcomes are not retried. Local pause, current heartbeat, task cancellation
and assignment revocation remain enforced by their owners. These endpoints use
the existing private UID-checked socket and initially support the Linux host bridge.

Unit contracts cover peer identity, exact-byte preservation, credential containment
and configured route refusal. This adapter supports Visor #219 / hypermesh-vscode #9.
