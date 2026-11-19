# AMD ROCm host image (scaffold)

This is **not** the AGX overlay and **not** a certified host class. The certified Jetson classes (AGX Orin and Seeed Super J4012) stay first.

The default `hypermesh-agent` binary is the AGX / Jetson image. On that image `backend=hip-rocm` POST `passed=false` with this fixed string:

```
This image does not run hip-rocm.
```

The Linux amd64 agent also supports the separate [managed Vulkan runtime](#managed-vulkan-leases).

## What this scaffold is

`internal/runtime/hip.go` is the start/stop path for `hip-rocm` (16GB+ class first). `ResolveBackend` returns that path **only** when this binary was built with `-tags rocm`. A runtime probe (`/dev/kfd`) is used at start; missing KFD fails honestly. This is not a TOPS or tokens/sec claim. TOPS is not tok/s.

`HSA_OVERRIDE` and `HSA_OVERRIDE_GFX_VERSION` are never set, and the gfx target is never guessed.

Cert still means **Fyber-published hashes**. `image_digest` stays `repo@digest`. This slice does not pull GHCR and does not fabricate a completion.

## How a future ROCm host image enables it

1. Build a **different** host image (not the AGX overlay):

   ```bash
   go test ./...
   go test -tags rocm ./internal/runtime ./internal/agent
   go build -tags rocm -o hypermesh-agent ./cmd/agent
   ```

   `go test ./...` without `-tags rocm` is the AGX/default cert path. Keep it green.

2. Ship that binary on a box that actually has ROCm and a 16GB+ class AMD GPU. The default Jetson image must not be rebuilt with `-tags rocm`.

3. Control plane still sends `runtime=nvidia` (a fixed field that is not overloaded) and `backend=hip-rocm`. Loaders stay `oci|gguf`. `disk-io` is not in the enum.

4. Workload listen path is still `0.0.0.0:8080` / `POST /v1/chat/completions`. `instance_check` still requires a real `choices[0].message.content`. The scaffold does not fake that.

5. Pin the host and workload with Fyber-published hashes. Uncertified catalog ids stay uncertified.

## Out of scope here

NVIDIA Jetson certified classes, public Thor, GHCR pull, fabricated tokens/sec, marketing TOPS as tokens/sec, `HSA_OVERRIDE`, and guessed gfx names.

## Multi-platform candidate

Linux AMD64 release payloads now use `rocm,cpu` build tags. HIP binds the exact
GGUF and catalog alias and pulls the pinned image. The existing HIP SDK/driver,
allocation, model-context and physical acceptance requirements still apply.
See [the platform matrix](../../docs/platform-releases.md).

## Managed Vulkan leases

The Plane job selects `backend=llama-cpp-vulkan` and `runtime=runc`. Install Docker
and the AMDGPU kernel driver on the host. The agent selects one AMDGPU render node
and refuses missing or ambiguous nodes. It gives the approved Vulkan image access
to that node and the read-only GGUF through the managed workload network. The
runtime image must provide RADV and a Vulkan-enabled llama-server. The upstream
`ghcr.io/ggml-org/llama.cpp:server-vulkan` channel provides that layout.

Configure `HYPERMESH_RUNTIME_IMAGE_REPOSITORIES` with the deployment-approved
repository. The Plane supplies the runtime image reference and the GGUF hash.
For a 32K profile set `HYPERMESH_LLAMA_CTX_SIZE=32768` in the agent service.
The Vulkan launch uses one slot and disables context shifting. The usual lease
health check, WireGuard forwarding, and stop/recovery behavior apply.
