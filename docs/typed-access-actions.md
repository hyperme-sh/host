# Typed action bridge

The private Visor bridge forwards current typed-action reviews and durable
admission to Conductor. It derives tenant, device, bot, assignment and session
from its trusted configuration and sends the existing short-lived credential
only on the child process's stdin. The Visor account never receives that
credential. `permission-action-admit` uses the configured dispatch journal;
there is no caller-selectable journal or alternate queue.

HTTPS and project-file operations execute in Visor under its user account.
The Host bridge also supports an optional `service_control` configuration:

```json
{"executable":"/usr/bin/systemctl","uid":1001,"gid":1001,"units":["worker.service"]}
```

The UID must match the configured companion UID and must be non-root. The
bridge exposes the current controller executable hash and configuration hash
through `/permission-service-context`. Restart requires a fresh admitted action
binding both hashes, the exact unit and UID. The executable is root-owned,
not group/world-writable, opened without following a final symlink, hashed and
executed through its open descriptor. The command is always `systemctl --user
--no-ask-password restart -- UNIT`, with fixed environment and no supplementary
groups. No shell, caller arguments, privileged system units or arbitrary
executables are exposed. User-service definitions remain owned by that user;
this permission controls the named user-manager operation, not the definition
or code inside that user's service.

The client must not automatically retry a missing response: admission has
already consumed the action ID and the operation may have started. Cancellation
terminates the local command but cannot undo a restart already accepted by the
user service manager.

Unit and contract checks cover identity/project binding, executable/config
changes, fixed arguments, credential containment, non-root credentials and
refusal of absent/expired admission.
