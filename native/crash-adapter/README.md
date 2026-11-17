# Native Host worker capture

This slice attaches to the direct macOS Metal worker. Containerized Linux workers
and confidential guests remain unsupported: they must not inherit the host's PID
namespace, raw-memory access or cleanup authority. The root-only Host cleanup
contract is prepared in Visor #284/#285. No install or activation occurs here.

The worker adapter, SDK and handler form one qualified bundle. CI builds the exact
shared source declared in Cargo.toml, runs Rust unit and native option contracts,
and retains a source-identified Actions archive. No version/tag/release changes
are required. To prepare the same bundle from source, use
`bash native/crash-adapter/build.sh VISOR_SOURCE OUTPUT` with the declared checkout.

Before configuration can enable capture, an administrator must install the bundle
under `/usr/local/libexec/hypermesh/crash-sdk`, with root ownership and no group or
other write permission. The matching Host cleanup LaunchDaemon must already be
installed and running under its dedicated label, using the root account's fixed
OS-profile storage. The SDK helper's `register-host` command refuses a conflicting
Visor authority registration. Installation does not enable reporting.

The Host agent uses `HYPERMESH_HOST_NATIVE_CRASH_ENABLED=1` only alongside its
existing reporting configuration and current recorded Terms acceptance. It adds
the trusted adapter to the direct worker using a generated run UUID. Missing
adapter preparation leaves ordinary worker execution available without capture.
The adapter independently requires the installed cleanup service, matching Terms
and enrollment, and the Host-specific SDK marker before starting Crashpad. It
never creates Visor consent or grants native SDK upload permission.

The SDK's DSN and proxy are empty, its transport is compiled out, and its upload
consent is permanently denied. Debug, automatic sessions and breadcrumbs are off.
The handler checks the current private enrollment and cleanup permission before
raw writes. One account-wide run, five reports, 32 MiB per report, 160 MiB total
and seven-day maximum retention apply. Configuration never resets that budget.

After its worker exits, Host requests writer shutdown, obtains the shared lock,
reads only numeric minidump header/exception fields, and deletes the raw run
before any sanitized event can be submitted. A malformed or unsafe dump produces
no report. No stacks, memory, strings, prompts, paths or secrets enter JSON. The
existing exact-event registration and single-attempt sender are reused. Abnormal
Host termination leaves cleanup to the installed service; reports are not revived
or automatically uploaded on restart.

Native capture is not attached to the trusted confidential runtime. Its profile,
billing policy and digest activation remain unchanged. Shared crash scenarios run
only through scheduled CI; unit/contract checks do not claim an installed host.
