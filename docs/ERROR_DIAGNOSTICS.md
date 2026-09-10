# Error diagnostics contract

Authentication and activation failures must report the operation that failed,
not an inferred explanation based on an English error string.

- Core authentication logs identify `event`, `stage`, and `error_code`.
  Method selection, feature negotiation, Grant decode/signature/validity,
  identity binding, device proof, replay, and admission are distinct stages.
- Runtime activation logs preserve the originating `error_code`, attach a
  typed `cause_code`, and retain the context chain. A rollback failure is a
  separate event; it must not overwrite the originating failure marker.
- Grant resolution uses typed stage/code values. HTTP status, transport,
  response decoding, report validation, subject binding, validity, and local
  persistence failures remain distinguishable. Validation identifies the
  mismatching field without printing credential values.
- Unknown errors are explicitly unclassified. Message substring matching is
  not a diagnostic classification contract. Retry policy is separate from the
  human-readable explanation.
- Cleanup failure must not be called policy preparation failure. A successful
  Core response with the wrong generation must not be called Core rejection.
- Logs must not contain secrets, Grant bodies, device proofs, or untrusted
  HTTP response bodies. Runtime error chains have control characters removed.

Remote authentication rejection deliberately remains uniform to avoid an
authentication oracle. Operators use controlled server logs to distinguish
the exact rejection cause; client-visible rejection alone is not evidence of
a particular credential or protocol defect.

Regression coverage is in `candy-cloud-sync` Grant field validation tests,
`candy-sdwan-agent` typed-cause and rollback tests, and Core Cloud authentication
stage and uniform remote rejection tests. This contract covers the audited
authentication/activation path; it is not a claim that every unrelated module
has been exhaustively audited.
