# Bootstrap Provider Snapshots

These files are validated, offline-safe bootstrap data. Runtime updates replace
them only after Candy Core parses the complete downloaded provider successfully.

| Installed file | Upstream | Source SHA-256 | Installed SHA-256 | Generated entries |
| --- | --- | --- | --- | ---: |
| `cn-ip.cidr` | `https://gaoyifan.github.io/china-operator-ip/china46.txt` | `53c14f1e12809c0afa97fc4556e99935c8cae157249f7ed6fee977030830f4fd` | `53c14f1e12809c0afa97fc4556e99935c8cae157249f7ed6fee977030830f4fd` | 10,006 |
| `gfwlist.domains` | `https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt` | `156591c393401ea28d099b9ffd255d4e3ed43a8c164cb8814dabc12c3139a38d` | `8b4cbea2cbebc441ed9653cb2ad1b4508d6b38be07f4895d7f80bdcdbd924e18` | 4,294 |

CN-IP snapshot reviewed and fetched: 2026-10-13 (6,533 IPv4 / 3,473 IPv6).
GFWList snapshot date: 2026-08-05.

The current upstream includes unannounced RIR-CN registration space. Its
address coverage expansion explains why it and the IPv4-only 17mon source
failed the old August baseline's reverse-overlap check. Current 17mon retains
98.4549% of this IPv4 baseline and 97.2534% of its own IPv4 space is covered
by this baseline, satisfying the existing 85% checks in both directions.
Upstream generator source inspected: gaoyifan/china-operator-ip at
`b2b8edc0ddd9cf2bc638ec77587301bbf84b8db9`.

`gfwlist.domains` is the normalized, sorted output of Candy Core's GFWList
parser, so its installed-file digest differs from the encoded upstream source.
