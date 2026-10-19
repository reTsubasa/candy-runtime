# SD-WAN activation recovery — 2026-10-19

## Confirmed failures

- Expired device certificates prevented Cloud synchronization. Runtime r156 adds explicit identity repair with retained Profile, network state and an identity backup. Cloud permits only a bounded renewal grace period; devices beyond it require administrator-authorized replacement enrollment.
- Hangzhou rejected generated peer TOML because discovery emits protocol preset `bbr_v1`, whereas Core transport TOML accepts `bbr-v1`. Runtime r157 explicitly translates supported protocol values and rejects unknown ones. Candy BBR remains enabled; no fallback algorithm is introduced.
- Core independently mapped the route-prefix quota (65536) into replay attachment capacity (maximum 4096). Core 0.3.65 separates those budgets. The queue and replay-window values emitted by Cloud are valid and must not be reduced to mask this defect.
- BWG server seed transport differed from the shared Proxy listener. The seed transport was aligned with the existing listener without changing authentication or restarting Proxy.

## Activation ordering

A PREPARE delivery may intentionally retain the previous candidate until the Cloud commit barrier opens. A different or expired previous candidate alone does not prove an HTTP 304 bug. The speculative forced-refetch change was reverted; it would not resolve a blocked multi-node barrier.

## Verification and rollout

Regression coverage checks all supported preset translations, rejection of unknown values, the production resource tuple with more than 4096 routes, and retained rejection of invalid replay windows and over-budget route tables. Run complete Runtime verification and Core process/TUN tests before publishing signed Core 0.3.65 and Runtime r157. Validate Hangzhou first, then server synchronization and readiness on HK/BWG. Certificate validity and a running process alone do not establish a working data plane.

Use signed central releases and transactional installers. Preserve node IDs, Profile, keys and infrastructure TUN. Confirm Cloud reports current/applied configuration and bidirectional overlay probes before declaring recovery complete. Published unsigned staging assets must be removed after signing.
