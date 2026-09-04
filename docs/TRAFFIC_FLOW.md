# Runtime traffic flow contract

The runtime has two independent data-plane modules. Their state, lifecycle,
policy reload, and failure recovery must not be coupled:

```text
client request
  -> DNS resolution and answer-to-route binding
  -> SD-WAN route/policy match (only when an authenticated SD-WAN activation is ready)
       match    -> candy0 TUN / SD-WAN stream
       no match -> ordinary Candy Proxy policy match
  -> Proxy policy match
       match    -> selected Candy Proxy node/transport
       no match -> local WAN
```

The Linux SD-WAN backend implements this contract with destination-specific
policy rules. A `0.0.0.0/0` SD-WAN route is valid only when Cloud explicitly
publishes a signed `RemoteEgress` declaration. Site-to-site declarations must
contain only their signed remote prefixes, so unrelated destinations fall
through to the ordinary Proxy policy.

Operational invariants:

- restarting or reloading SD-WAN does not stop, reload, or mark the Proxy
  module failed;
- restarting or reloading Proxy does not withdraw healthy SD-WAN routes;
- withdrawing SD-WAN removes only SD-WAN-owned routes and leaves Proxy rules;
- a Proxy fallback is `active` only with Proxy readiness/evidence; otherwise
  the final fallback is `local_wan` and is reported as `degraded`;
- process existence, an RTT probe, or SD-WAN readiness alone is not evidence
  that the Proxy data plane is carrying traffic.

