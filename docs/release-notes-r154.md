# Runtime 0.4.0-r154 status and DNS rule repair

## Observed failures

On 192.168.2.1, status JSON embedded an old transport warning containing
unescaped double quotes. BusyBox awk handles gsub replacement escapes
differently from the host awk. LuCI discarded the malformed status snapshot
and displayed the fallback 0.4.0-r1 instead of installed r153. This was a data
serialization failure, not CSS truncation.

After an empty DNS policy row was added in LuCI, provider downloads succeeded
but runtime generation failed. write_dns_rule did not bind its section
argument, so even populated DNS rules could fail or be misread. The reload
failure only reached syslog and the browser displayed an empty generic error.

## Changes

- Encode JSON characters without awk replacement-string escaping, including
  quotes, backslashes, control characters and trailing newlines, in Runtime
  status and both update/Core operation managers.
- Validate generated status JSON before replacing the last valid snapshot.
- Remove fabricated version/revision fallbacks from the overview endpoint.
- Read each DNS rule's actual section. Ignore a blank default direct/suffix
  draft with a warning; populated invalid rules remain rejected.
- Return DNS validation code, module, section and detail on stderr so LuCI
  activation errors contain the cause. Failed configuration generation keeps
  the current runtime process and configuration active.
- Declare coreutils-stat and use the existing LuCI filesystem API as a fallback
  on minimal images without stat. Failure to read a timestamp is reported and
  does not pretend a valid existing provider is permanently expired. Missing
  or invalid provider contents still trigger a download. This removes repeated
  download/reload attempts caused by the missing applet on the IPQ40xx device.

Core 0.3.63 remains the deployed Core; this repair is in Runtime r154.
Regression tests cover JSON round trips, actual section binding, exact/suffix
DNS rules, node targets, blank drafts and invalid type/domain/target rejection.
