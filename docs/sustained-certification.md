# Automatic sustained certification

The host advertises `certification_protocols: ["sustained-decode-v2"]` alongside its software inventory and build information. Plane queues certification after inventory changes or expiry. This work uses the existing authenticated job channel and lease exclusion; it does not require an operator to run a benchmark.

Each assignment binds a model hash, immutable runtime image and full context window. A temporary single-slot runtime first verifies that context with 16 generated tokens, then produces 64 deterministic tokens. The throughput denominator is llama.cpp's server decode time, excluding HTTP and prompt processing. Complete token counts and finite positive timing are required. Context timing stays separate. The model hash is checked before and after execution, and uncertain cleanup fails the job.

The host persists the result before posting it to `/agent/certification/sustained-result`. Retries reuse the exact sample. Plane and AIuditor use a separate versioned class reference; the new rate is never compared with or written over a legacy reference. The existing performance and thermal bands still apply. Missing references require a declared lab host's qualification before ordinary hosts can pass.

Older Plane responses without the explicit protocol cannot run this assignment. Legacy assignments retain their existing wire contract. Shared-host validation runs only in scheduled CI; PR checks cover unit and contract behavior.
