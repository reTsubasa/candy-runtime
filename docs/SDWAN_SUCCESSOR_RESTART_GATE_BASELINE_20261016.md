# Successor restart gate baseline

The successor restart scenario intentionally terminates the server Core after
the original MBB rounds. That recovery is expected to replace the business
worker and increment its `worker_epoch`; it must not recreate or mutate the
retained TUNIO infrastructure.

The gate now captures the exact post-recovery records before starting ordinary
successor redial. For TUNIO, the post-recovery record must equal the original
record byte-for-byte except for the new Core `worker_epoch`. PID, process start
ticks, executable identity, binding, readiness token, authorization deadline,
policy generation, infrastructure generation, and `io_epoch` remain fenced.
For ordinary redial and the subsequent post-restart renewal, both the server
Core and TUNIO records must remain exactly equal to this post-recovery
baseline.

This corrects the prior false failure where the fixture compared a deliberately
killed Core's pre-recovery TUNIO record (`worker_epoch=2`) with the valid
post-recovery record (`worker_epoch=3`). It does not relax any ownership or
replacement assertion. The Core-side `lane_staged_owner_requires_commit`
rejections during the redial race remain active-owner fencing; the gate still
requires a later exact committed successor and uninterrupted packet/proxy
checks.
