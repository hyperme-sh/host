# Remote software recovery

The host owner can request an immediate check or a revert through Plane:

`POST /api/v1/hypermesh/devices/{device_id}/software`

Use the existing tenant and host-owner authentication, with this JSON body:

```json
{
  "request_id": "a8c86e43-1a8f-4565-bb9c-f8ee174dc671",
  "action": "update",
  "expected_sha256": "<installed executable SHA-256>",
  "target_sha256": "<approved signed executable SHA-256>",
  "expires_at": "<UTC timestamp within 24 hours>"
}
```

The target is a binary selection for this operation. It does not pin a running
service or change the TEST channel. An update must match the current signed
channel candidate. A revert must match a retained, signed older binary in the
same channel. Neither operation accepts a download URL or changes OS packages.

The host checks the control endpoint on its job tick while idle. It defers while
a lease, unacknowledged result, or maintenance hold exists. It saves the command
before changing files and reconciles it after restart. Transport and activation
failures that restore the previous executable retry with a bounded delay until
expiry. A restored process reports a failed activation; a healthy target process
reports applied only after startup confirmation. Normal certification still
controls rental eligibility.

Read `GET /api/v1/hypermesh/devices/{device_id}/software/{request_id}` for the
outcome. An accepted request is pending, not applied. Reusing the ID with identical
parameters returns the same request; changing its parameters is refused. There
is one pending request per device, and its outcome must be reconciled before
another is accepted. Older Plane instances return 404 on the optional host poll;
older hosts never receive these commands through their workload queue.

Version, build number, channel and commit travel in the next host heartbeat.
Production publication and manual tag operations retain their existing authority.
