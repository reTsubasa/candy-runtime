# Runtime 0.4.0-r153 rule updates

- Add independent manual GFWList and China-IP update controls in Advanced.
- Show structured error codes, modules and detailed validation/load failures.
- Bound download and activation time, prevent duplicate browser submissions,
  validate CSRF tokens and preserve rejected source configuration.
- Verify active rule content before reporting a successful hot load.
- Refresh the signed packaged CN-IP baseline to the reviewed October 13
  upstream snapshot, keeping the existing coverage protection threshold.

Install Core 0.3.63 as well to accept IPv4-only/IPv6-only update candidates.
Version 0.3.62 still requires dual-stack candidates. The Runtime and Core
release signatures and normal deployment health/rollback gates remain required.

Regression coverage includes successful loading, rejected download, activation
failure, stopped service, unselected providers, source persistence failure,
deadlines and CSRF checks. Actual LuCI behavior has been verified on IPQ40xx
at desktop/mobile sizes; post-release deployment verification is recorded
separately.
