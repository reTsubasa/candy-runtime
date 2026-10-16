# Shared worker control error classification

## Observed failure

The negotiated shared-pool v9 gate reported two distinct classifications for
Linux EAGAIN. Errors retained under `read bounded process-control message`
were retryable. Shared-domain completion errors appeared as a bare
`Resource temporarily unavailable (os error 11)` and were classified as
permanent, leaving the affected domain in `waiting_plan`.

## Root cause and correction

`BusinessWorker::{try_wait,kill,wait}` previously converted the shared
domain's `anyhow::Error` into `std::io::Error::other`. The boxed anyhow adapter
hid the original typed I/O cause from the supervisor's downcast checks.
Matching the displayed error text would incorrectly depend on operating
system wording and errno numbering.

These internal methods now return `anyhow::Result` and retain the shared
control error directly. Dedicated child errors also retain their original
I/O type. Shared control connect, write, shutdown, and response-read failures
carry operation context without replacing the typed cause. The supervisor
also inspects a typed inner I/O error when an I/O wrapper is present.

The shared classifier remains restricted to existing transient signals,
errno values, and I/O kinds. Invalid signed authorization and invalid input
remain permanent errors. Initial readiness cleanup is a separate recovery
path: preserving the error type does not by itself preserve Core/TUNIO
records after an unknown readiness result.

## Verification

- A native macOS reproducer of the previous opaque anyhow-to-I/O wrapper
  failed its EAGAIN retry assertion, confirming the conversion loses the
  required type. macOS EAGAIN is errno 35, so no Linux errno string is used.
- Native focused `runtime_agent::tests`: 8 passed, including contextual
  EAGAIN/ECONNRESET/ETIMEDOUT and permanent authorization/input cases.
- Native `shared_worker::tests` covers terminal completion classification.
- A Linux-only regression creates an authenticated local Unix endpoint,
  leaves a completion response outstanding beyond the configured one-second
  timeout, and asserts `BusinessWorker::try_wait` retains a typed retryable
  I/O cause. This test must run in the coordinated Linux gate; native macOS
  results do not exercise Linux process identity checks.

No online service changes or full Docker gates are performed by this
focused correction. Full negotiated drain and scaling acceptance requires
the coordinated end-to-end run.
