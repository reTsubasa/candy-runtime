# IPQ40xx Core and Runtime compatibility

## Release pair

Runtime 0.4.0-r151 and Rust Core 0.3.62 retain process API 1, Core API 1,
wire protocol 0.3, and the existing transport settings.

## Selection contract

- Firmware: OpenWrt 25.12.x, with a numeric patch version.
- Runtime build SDK: 25.12.4; patch compatibility does not change build provenance.
- Device: ipq40xx subtargets with package ABI arm_cortex-a7_neon-vfpv4
  (the underscore spelling is also recognized).
- Core: armv7-unknown-linux-musleabihf, static musl, ARMv7 EABI hard-float.
- Published architecture: armv7. Core now derives its reported architecture
  from Cargo's actual build target, rather than the broad Rust arm family.

The ARMv7 artifact is shared by compatible devices; it is not a universal
ARM artifact. CPU features, floating-point ABI, libc and package ABI must
remain compatible. No Cortex-A7-specific performance tuning is introduced.

## Fixed failures

The updater rejected 25.12.5 before fetching the signed catalog. It now accepts
numeric patches in 25.12.x while retaining target and package ABI validation.
Missing Runtime platform entries no longer suppress an independently compatible
Core. Present entries still undergo full URL, size, digest and API validation.

Legacy signed Core manifests report armv7 but their executable reports arm.
The manager accepts this specific pair only after verifying the full ARMv7
hard-float target, exact device package ABI, signature and executable digest.
New Core binaries report armv7 consistently with their signed manifest.

## Verification and rollout

Manager regression tests cover patch versions, wrong package ABIs, legacy
architecture output, signature/digest checks and rollback. Actual ARM artifacts
must also be probed under Cortex-A7 emulation before publication. Firmware patch
compatibility tests are simulated; physical IPQ40xx installation requires access
to the device. An r113 device blocked by its old version gate needs manual
installation of the new Runtime APK pair once; the new updater then works.
