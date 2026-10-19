//! Version-2 authorization deadlines and Core reports share Linux BOOTTIME.
use candy_netd_proto::v2::ForwardOwner;

#[cfg(target_os = "linux")]
pub fn now_ms() -> std::io::Result<u64> {
    let mut value = nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime only writes to the valid stack timespec.
    if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    timespec_ms(value.tv_sec as i64, value.tv_nsec as i64)
}

#[cfg(any(target_os = "linux", test))]
fn timespec_ms(seconds: i64, nanos: i64) -> std::io::Result<u64> {
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid BOOTTIME value");
    if !(0..1_000_000_000).contains(&nanos) {
        return Err(invalid());
    }
    u64::try_from(seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .and_then(|millis| millis.checked_add(nanos as u64 / 1_000_000))
        .ok_or_else(invalid)
}

pub(crate) fn proof_is_fresh(now: u64, reported: u64) -> bool {
    reported <= now.saturating_add(50) && now.saturating_sub(reported) <= 5000
}

pub(crate) fn owner_is_live(owner: &ForwardOwner, now: u64) -> bool {
    now < owner
        .auth_deadline_mono_ms
        .min(owner.lease_deadline_mono_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspend_offset_does_not_turn_actual_boottime_report_into_future_proof() {
        let monotonic_before_resume = 10_000;
        let suspend_offset = 60_000;
        let boot_now = monotonic_before_resume + suspend_offset;
        assert!(proof_is_fresh(boot_now, boot_now - 20));
        assert!(!proof_is_fresh(monotonic_before_resume, boot_now - 20));
        assert!(!proof_is_fresh(boot_now, boot_now + 51));
        assert!(!proof_is_fresh(boot_now, boot_now - 5001));
    }

    #[test]
    fn suspended_time_counts_toward_authorization_and_lease_expiry() {
        let owner = ForwardOwner {
            domain_id: [0; 16],
            signed_generation: 1,
            worker_epoch: 1,
            fencing_token: 1,
            auth_deadline_mono_ms: 20_000,
            lease_deadline_mono_ms: 30_000,
        };
        assert!(owner_is_live(&owner, 10_000));
        assert!(!owner_is_live(&owner, 70_000));
        assert!(!owner_is_live(&owner, 20_000));
        let lease_first = ForwardOwner {
            lease_deadline_mono_ms: 15_000,
            ..owner
        };
        assert!(!owner_is_live(&lease_first, 15_000));
    }

    #[test]
    fn invalid_kernel_values_fail_instead_of_saturating_deadline() {
        assert_eq!(timespec_ms(1, 234_000_000).unwrap(), 1234);
        for (seconds, nanos) in [(-1, 0), (0, -1), (0, 1_000_000_000), (i64::MAX, 0)] {
            assert!(timespec_ms(seconds, nanos).is_err());
        }
    }
}
