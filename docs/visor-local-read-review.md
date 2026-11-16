# Private local-read review adapter

The configured Visor UID may POST `/permission-read-review` on the existing
private bridge. The request supplies a UUID request ID, exact action, selected
template and optional expected policy revision. Its project must equal the
root-configured machine workspace, and the preview and machine bindings must
match. Other UIDs and caller-supplied identity fields are refused.

The bridge invokes Conductor's `permission-read-review` with configured HTTPS
owners and supplies the machine credential only over the trusted child's stdin.
It checks the returned nonce and identity before returning the bounded response.
Host does not read the file; Visor performs OS access as its own user after
matching verification. Preview behavior remains unchanged.

Supports Conductor #68 and depends on Conductor #80. Unit contracts cover private
credentials, current binding, request IDs, peer UID and project override refusal.
