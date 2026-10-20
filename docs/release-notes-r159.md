# Candy Runtime 0.4.0-r159

This revision integrates upstream identity recovery and ready-path probing with
infrastructure-preserving policy activation. Route-only changes reconcile routes
in place, update firewall state atomically only when its policy changes, and keep
the existing TUN and active owner. Signed inbound policy catalogs are included in
immutable runtime activations. Exact pending policy recovery preserves the original
transaction and physical authorization ceiling across lost acknowledgements and
controller restarts.

Expired identities can be repaired through the Runtime command or LuCI by importing
a Cloud administrator recovery file. The staged key bundle and interrupted
publication are recoverable without clearing the Profile or data-plane state.
The release includes the experimental managed agent feature used by deployed
SD-WAN workers; Core remains an independent signed artifact.

Pre-release checks include full Runtime workspace tests, strict Clippy, route
transaction tests, product identity recovery/LuCI upload tests, and signed renewal
integrity checks. Hardware-link throughput and a continuous production soak are
separate acceptance tasks; this release does not claim those results.

Historical uncommitted generated evidence and unintended packaging deletions were
preserved in stash `a83debf50fe4cd9d1a08329863edff3f0c9f7ff7`; source changes were
reviewed and committed selectively. The six packaging scripts remain present.
