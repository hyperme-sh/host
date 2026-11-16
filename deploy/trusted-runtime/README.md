# Trusted CPU token meter implementation

Tracking: [Host #216](https://github.com/hyperme-sh/hypermesh-host/issues/216).
Owner prerequisite: [Plane #155](https://github.com/hyperme-sh/hypermesh-plane/pull/155),
which adds signed grant issuance times and nonce-bound requests.

This directory is an implementation under development. It is not installed by
Host setup, selected by the ordinary CPU runtime, or enabled for billing.
The ordinary Docker runtime cannot satisfy the confidential execution boundary.

## Counter and wire contract

Policy `processed-input-accepted-output-v1` bills processed input plus accepted
output. Processed input excludes cache hits. Hidden output is a subset of
accepted output, never an extra charge. Cache hits and rejected speculative
proposals are recorded without charging. Prompt counts remain record-only.
Existing per-1,000-token pricing and failed-token refunds are unchanged.

The bounded initial engine uses the pinned llama.cpp commit in `engine/source.json`.
It has fresh request contexts, greedy decoding, at most 2048 input tokens and
128 accepted output tokens. Cache reuse and speculative decoding are disabled,
so their actual counters are zero. Model and tokenizer digests both identify the
same GGUF file for this profile. Templates use llama.cpp's built-in template
support, not arbitrary Jinja execution. Control, end, and empty output tokens
are hidden; all other generated pieces, including reasoning text, are emitted
and counted as accepted output. No accelerator backend is supported.

Input counts advance after successful decode, in chunks of at most 32 tokens.
Accepted output advances once per selected token. Each cumulative count is
signed and journaled, then anchored at Plane before the next permitted step or
output delivery. A failed decode, lost anchor reply, or expired grant leaves an
uncertain request disputed. A bounded step can finish after disconnection;
this implementation does not promise instantaneous stopping.

The Go package verifies Plane's signed response domain, complete request hash,
tenant, lease, Gateway, immutable budgets, and grant identity. A fresh start
nonce prevents substitution of a prior first-start reply. The grant interval is
anchored to the protected clock sample before the initial send, subtracting one
second for timestamp quantization and the qualified rate allowance. Replayed
starts never authorize work; late renewals cannot resurrect an expired grant.

The count-only journal uses atomic replacement, file and directory sync, strict
JSON parsing, signatures, hash continuity, and monotonically increasing counts.
After reopening, it serves existing records read-only and never resumes work.
A local terminal record still needs its matching Plane anchor for settlement.
Missing terminal records do not imply zero work. No private key, prompt, output,
token ID, or prompt hash is stored in the journal.

## Remaining source requirements before Host #216 can close

- Measured confidential guest boot and immutable workload loading. Hashing files
  on an ordinary host does not establish the required boundary. The supervisor,
  kernel, libraries, template policy, and model loading path must be covered by
  the approved profile. Provider-writable model files are not acceptable.
- Real protected-time adapter and qualification of pause, drift, and rollback
  behavior. The `ProtectedClock` interface is not a hardware implementation.
- Guest-only ephemeral key generation and SNP quote collection, bound to the
  independent verifier's fresh challenge and exact workload profile. An ordinary
  host key or local capability report cannot replace independent verification.
- Authenticated Gateway TLS terminating inside the guest, binding the complete
  inference body and limits to the admitted request; scoped status/final APIs.
- Host launch and shutdown wiring with no ordinary CPU fallback, plus unit and
  contract tests of the complete guest path.

Do not persist a guest private key merely to serve historical final records.
Recovery can return the original signed records and public key for verification
against Plane's stored session and anchor. A new guest session must not renew or
execute an old request.

Independent verifier configuration, approved measurements, vendor policy, and
scheduled qualification are tracked in
[Infra #1638](https://github.com/FyberLabs/infra/issues/1638). Those configuration
steps do not replace the unfinished source requirements above. Gateway #70 and
#69 remain downstream. Digest billing stays disabled.

## Unit and contract validation

`go test -race ./internal/trustedmeter` checks the wire fixture produced by
Plane's Python signer, owner grants, replay/expiry/rollback handling, budgets,
journal restart, and file digests. `counter-contract` checks the isolated C++
count hook and failed decode behavior. The CI engine job builds the pinned CPU
source without downloading a model or running inference.
