# Active Proxy Drain Wire Gate

## Scope

This gate runs the real Runtime `candy-client` wrapper and Linux Rust Core in
two isolated Linux containers. It does not modify production services. The
server explicitly authorizes `proxy_drain_v1`; the default recommended feature
set is not sufficient evidence of negotiation.

```sh
python3 scripts/proxy-gate/run.py \
  --binary /absolute/path/to/linux/candy-core \
  --evidence /absolute/path/to/new/evidence-directory \
  --active-drain-only --seconds 1 --rounds 1 --warmup 1
```

The fixture uses a private Docker local volume for the control socket because
macOS VirtioFS does not support Unix socket pathname chmod. It requires socket
mode `0600` and removes only its own containers and volume.

## Required Evidence

- Passive status confirms the drain capability is negotiated and authorized.
- Existing TCP and UDP egress sockets belong to an exact worker ID, owner
  epoch and PID, proven through kernel socket inodes and the worker's owned
  `driver-ID-EPOCH.sock` listener.
- Wrong-token and incomplete requests receive structured errors, and the same
  existing TCP and UDP flows remain usable afterwards. The incomplete request
  times out in two seconds.
- The server sends and the client receives the negotiated notice. Its remaining
  deadline cannot exceed the original requested 6000 ms.
- Existing flows exchange valid bytes after receipt of the notice. TCP completes
  its final tail and FIN. UDP retains its original PID, socket inode and source
  port.
- A new admission reaches the receipt's complete replacement tuple before the
  held old flows finish. A new physical worker may have the same epoch as the old
  worker. ID and PID must distinguish the incarnations.
- No new admission attempt may fail. Retrying in the generator is diagnostic;
  it cannot turn a TCP reset into a passing strict gate.
- Twenty-four new UDP flows use distinct source ports and send their first
  packet exactly once during drain. Every complete payload and original source
  port must echo correctly from the forwarding listener. At least one flow must
  reach the replacement before the held old flows finish. Generator
  retransmissions are forbidden.
- Drain, OS reap and replacement readiness receipts are exact. The original
  deadline completes within the fixture's 2 s collection tolerance. Master PID,
  start time and public QUIC listener inode remain unchanged.

## Negative Baseline

Evidence: `docs/artifacts/sdwan-20261016/proxy-active-drain-v3-strict/`
in the parent workspace. Binary SHA-256:
`98c0dc6d11f9be3f6d1d266547b3f458cf57561408ded9de972ed3c776a1aced`.

The strict result is **FAIL**. Sixteen component gates pass; the only failing
component is `new_admission_no_error_gate`.

The old tuple `(1, 1, 51517)` preserves TCP tail/FIN and the original UDP flow.
The replacement tuple `(2, 1, 51659)` accepts new traffic before the held old
flows complete. The 6000 ms drain receipt arrives after 6.477 s. Public listener
inode `6246785` is unchanged. Mode 0600, wrong-token rejection and partial-request
timeout pass.

One new TCP request is reset during notice propagation. The server rejects the
already sent Open with `code=5 resource_exhausted`, module `proxy_worker_drain`,
reason `worker_draining`. The client receives the drain notice, then reports
`fixed proxied TCP ended: session rejected`. The replacement transport becomes
ready shortly afterwards. This identifies a client retry gap for an explicit
negative admission result; it is not evidence that an existing TCP or UDP flow
was lost.

The first-packet probe in
`docs/artifacts/sdwan-20261016/proxy-active-drain-v4-udp-strict/` also fails against
the same candidate. Two of 24 distinct UDP sources time out at drain admission
(sequences 2 and 3). Each sends one packet exactly once; the generator performs
zero retransmissions. The other 22 replies preserve the complete payload and
local source-port marker. New UDP reaches the replacement during overlap;
held old TCP/UDP, authenticated notice, exact receipt, master identity and public
listener identity pass. The strict TCP probe happens to pass in this run.
Together these negative baselines expose both TCP and UDP admission races.

## Corrected Candidate Result

Both strict runs pass:

| Evidence directory in parent workspace | Old worker tuple | Replacement tuple | UDP first packets | TCP attempt failures |
| --- | --- | --- | --- | --- |
| `docs/artifacts/sdwan-20261016/proxy-active-drain-v5-strict/` | `(1,1,68472)` | `(2,1,68579)` | 24/24 | 0 |
| `docs/artifacts/sdwan-20261016/proxy-active-drain-v6-strict/` | `(1,1,69626)` | `(2,1,69815)` | 24/24 | 0 |

Both use binary SHA-256
`de7e11c8d457593e82544518479974182cd83a4c40afbe9287ce5e3828a2f324`.
The client retains unread TCP input after a definitive negative admission ACK
under authorized drain context, and retains a new UDP flow's first packet while
waiting for authenticated replacement within its original deadline.

The server log proves that the UDP race occurs: v5 rejects three new UDP Opens
while quiescing; v6 rejects one. All 48 first packets nevertheless receive exact
replies, with one send per flow and zero generator retransmissions. Existing
TCP tail/FIN, original UDP owner/socket/source port, negotiated notice,
replacement overlap, control authentication/timeout, exact OS retirement
receipt, master incarnation and public listener inode all pass. The v6 drain
receipt arrives in 6.388 s for its original 6000 ms request; its public listener
inode stays `6393866`.

This candidate still logs `worker_epoch_stale` when the manager redundantly
requests drain after the worker has already exited. The parent is fixing that
retirement logging/coordination path separately. The exact final ELF must be
retested after that fix; the two passing data-plane runs do not certify later
source changes.

This report does not claim physical-platform, production, complete compatibility
matrix, performance, or long-duration acceptance.

## DNS Follow-Up

Read-only review identified a separate foreign-egress DNS transition gap:

- `run_multinode_production_dns_forward` converts a temporarily draining route
  selection into no selected transport. Its foreign-egress attempt then returns
  `NoAnswer` without waiting for the authenticated replacement.
- `execute_multinode_dns_attempts` captures one `ProductionDnsRuntime`.
  `DnsTunnelPool::query` retries against that same transport and returns an
  admission or response failure directly. A new/refilled DNS tunnel selected
  just before drain therefore cannot reselect the published replacement within
  the current query's original deadline.

This can fail the current foreign DNS attempt at the transition; it does not
prove a permanent outage, because subsequent queries can select the new
transport. The active flow fixture does not yet exercise DNS query forwarding.
