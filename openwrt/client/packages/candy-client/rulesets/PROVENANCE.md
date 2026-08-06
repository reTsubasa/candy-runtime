# Bootstrap Provider Snapshots

These files are validated, offline-safe bootstrap data. Runtime updates replace
them only after Candy Core parses the complete downloaded provider successfully.

| Installed file | Upstream | Source SHA-256 | Installed SHA-256 | Generated entries |
| --- | --- | --- | --- | ---: |
| `cn-ip.cidr` | `https://gaoyifan.github.io/china-operator-ip/china46.txt` | `5220ab4fbf03bb6fa003e7928bb072fe549fefd274269992b3cc817e25bf8ba3` | `5220ab4fbf03bb6fa003e7928bb072fe549fefd274269992b3cc817e25bf8ba3` | 5,814 |
| `gfwlist.domains` | `https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt` | `156591c393401ea28d099b9ffd255d4e3ed43a8c164cb8814dabc12c3139a38d` | `8b4cbea2cbebc441ed9653cb2ad1b4508d6b38be07f4895d7f80bdcdbd924e18` | 4,294 |

Snapshot date: 2026-08-05.

`gfwlist.domains` is the normalized, sorted output of Candy Core's GFWList
parser, so its installed-file digest differs from the encoded upstream source.
