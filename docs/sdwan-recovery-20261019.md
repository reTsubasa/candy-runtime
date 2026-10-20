# SD-WAN activation recovery — 2026-10-19

## Confirmed failures

- Expired device certificates prevented Cloud synchronization. Runtime r156 adds explicit identity repair with retained Profile, network state and an identity backup. Cloud permits only a bounded renewal grace period; devices beyond it require administrator-authorized replacement enrollment.
- Hangzhou rejected generated peer TOML because discovery emits protocol preset `bbr_v1`, whereas Core transport TOML accepts `bbr-v1`. Runtime r157 explicitly translates supported protocol values and rejects unknown ones. Candy BBR remains enabled; no fallback algorithm is introduced.
- Core independently mapped the route-prefix quota (65536) into replay attachment capacity (maximum 4096). Core 0.3.65 separates those budgets. The queue and replay-window values emitted by Cloud are valid and must not be reduced to mask this defect.
- BWG server seed transport differed from the shared Proxy listener. The seed transport was aligned with the existing listener without changing authentication or restarting Proxy.

## Activation ordering

A PREPARE delivery may intentionally retain the previous candidate until the Cloud commit barrier opens. A different or expired previous candidate alone does not prove an HTTP 304 bug. The speculative forced-refetch change was reverted; it would not resolve a blocked multi-node barrier.

## Verification and rollout

Regression coverage checks all supported preset translations, rejection of unknown values, the production resource tuple with more than 4096 routes, and retained rejection of invalid replay windows and over-budget route tables. Run complete Runtime verification and Core process/TUN tests before publishing signed Core and Runtime r157. Validate Hangzhou first, then server synchronization and readiness on HK/BWG. Certificate validity and a running process alone do not establish a working data plane.

Use signed central releases and transactional installers. Preserve node IDs, Profile, keys and infrastructure TUN. Confirm Cloud reports current/applied configuration and bidirectional overlay probes before declaring recovery complete. Published unsigned staging assets must be removed after signing.

## Deployment evidence (completed 2026-10-19)

Signed Runtime `0.4.0-r157` (source `7dfdafe924ed8f644a932c32c4f585e9457b0bc7`) and Core `0.3.66` (source `515d83880994022a6932a4ce076109f10d719d02`) are deployed on HK, BWG and Hangzhou. Core 0.3.66 additionally fixes normal SD-WAN help returning a failure status, discovered by the full Linux process-API regression. Central signing and finalize runs were 39233407659 and 39233453887; pinned-key signatures and artifact hashes verified; stable catalog sequence 291. Unsigned staging candidates are absent.

Runtime verification and 110 cloud-sync tests passed. Core process/TUN Clippy and Linux library/integration suites passed, including 151 Core process unit tests, 10 process-API tests and real Proxy workers. The optional external-Core Runtime Docker gate was skipped; it is not included in these claims.

Hangzhou required explicitly authorized offline filesystem maintenance after backup: a 122 MiB ext4 filesystem occupied a 14.7 GiB partition, and online resize was rejected. Booted into RAM without firmware/partition changes, took a clean offline snapshot, repaired/resized/checked the filesystem and rebooted. Root is now about 14.5 GiB. Original network/Candy/identity hashes matched after reboot. Private backups were retained locally and on the node.

After the Core fix, deployment exposed a second listener owner: standalone Proxy overlapped with the signed unified server on the same port. Both signed server activations already contained the existing Proxy users. Keep `candy-server.service` and `candy-cloud-sync.timer` enabled and the overlapping standalone `candy-proxy.service` disabled; do not re-enable both profiles on the same endpoint. Ordinary Proxy authentication was verified after the switch. This records the existing unified service deployment and does not claim a new production master/worker topology was introduced during recovery.

Cloud reports 6/6 candidates ready, all three devices current/active, no pending or failed applies. All three real Core statuses show `data_plane_active`, 2/2 peers and no failed prefixes. Hangzhou source 192.168.1.1 reached 1.1.1.1 and 8.8.8.8 through configured BWG egress (3/3 replies each, about 149 ms). BWG from its authorized 172.17.0.0/16 source reached a real Hangzhou LAN host (3/3 replies, about 147 ms); the temporary loopback test address was removed. HK has no locally advertised subnet; its two authenticated packet-stream probes are ready. An initial HK Docker-source test was correctly rejected by anti-spoofing because that prefix belongs to BWG; authorization was not weakened.

This is bounded functional connectivity evidence. No production load/fault injection, long-duration or throughput acceptance was performed. Browser E2E was unavailable; identity recovery used the formal administrator API and Runtime transaction. Below-requested inherited descriptor limits in non-root validators/OpenWrt SD-WAN remain a separate deployment-policy warning, not the engine initialization cause.
