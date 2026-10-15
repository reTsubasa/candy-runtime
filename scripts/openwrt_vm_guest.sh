#!/bin/sh
set -eu

root=/tmp/candy-gate
evidence=$root/evidence
mkdir -p "$evidence"
exec 2>&1
trap 'rc=$?; logread >"$evidence/logread.log"; ubus call service list >"$evidence/final-services.json"; exit "$rc"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
test "$(cat /proc/1/comm)" = procd || fail 'PID 1 is not procd'
cat /etc/openwrt_release >"$evidence/openwrt-release"
ubus call system board >"$evidence/board.json"
real_netd=false
if [ -f "$root/candy-netd" ]; then
    chmod 755 "$root/candy-netd"
    "$root/candy-netd" --help >"$evidence/netd-help.log"
    real_netd=true
fi

cat >"$root/infrastructure" <<'EOF'
#!/bin/sh
set -eu
root=/tmp/candy-gate
if [ -x "$root/candy-netd" ]; then
    exec "$root/candy-netd" --protocol-v2 --socket "$root/netd.sock" \
        --allowed-uid 0 --allowed-gid 0 --infrastructure-journal "$root/netd.journal"
fi
echo "$$" >"$root/infrastructure-probe.pid"
trap 'exit 0' TERM INT
while :; do sleep 1; done
EOF
cat >"$root/worker" <<'EOF'
#!/bin/sh
set -eu
root=/tmp/candy-gate
echo "$(cut -d ' ' -f 1 /proc/uptime) $$" >>"$root/attempts"
test ! -f "$root/fault" || exit 78
if [ -x "$root/candy-netd" ]; then
    "$root/candy-netd" --probe-socket "$root/netd.sock" --probe-protocol v2
else
    test -s "$root/infrastructure-probe.pid"
fi
echo "$$" >"$root/worker-ready.pid"
trap 'exit 0' TERM INT
while :; do sleep 1; done
EOF
chmod 755 "$root/infrastructure" "$root/worker"
cat >/etc/init.d/candy-platform-probe <<'EOF'
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=95
start_service() {
    procd_open_instance infrastructure
    procd_set_param command /tmp/candy-gate/infrastructure
    procd_set_param respawn 3600 1 3
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
    procd_open_instance worker
    procd_set_param command /tmp/candy-gate/worker
    procd_set_param respawn 3600 1 3
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
chmod 755 /etc/init.d/candy-platform-probe
pid() {
    ubus call service list '{"name":"candy-platform-probe"}' |
        jsonfilter -e "@[\"candy-platform-probe\"].instances.$1.pid" || true
}
wait_ready() {
    i=0
    while [ "$i" -lt 20 ]; do
        current=$(pid worker)
        [ -n "$current" ] && [ -s "$root/worker-ready.pid" ] &&
            [ "$(cat "$root/worker-ready.pid")" = "$current" ] && return 0
        i=$((i + 1)); sleep 1
    done
    fail 'worker did not become ready within 20 seconds'
}
stop_probe() {
    old_infrastructure=$(pid infrastructure)
    old_worker=$(pid worker)
    /etc/init.d/candy-platform-probe stop
    i=0
    while [ "$i" -lt 15 ]; do
        infrastructure_alive=0; worker_alive=0
        [ -z "$old_infrastructure" ] || ! kill -0 "$old_infrastructure" 2>/dev/null || infrastructure_alive=1
        [ -z "$old_worker" ] || ! kill -0 "$old_worker" 2>/dev/null || worker_alive=1
        [ "$infrastructure_alive" -eq 0 ] && [ "$worker_alive" -eq 0 ] && return 0
        i=$((i + 1)); sleep 1
    done
    fail 'test instances did not stop within 15 seconds'
}
echo 'stage=procd_start'
/etc/init.d/candy-platform-probe start
wait_ready
infrastructure_before=$(pid infrastructure)
worker_before=$(pid worker)
[ -n "$infrastructure_before" ] && [ -n "$worker_before" ] || fail 'missing service instance'
/etc/init.d/candy-platform-probe start
sleep 2
[ "$(pid infrastructure)" = "$infrastructure_before" ] || fail 'duplicate start replaced infrastructure'
[ "$(pid worker)" = "$worker_before" ] || fail 'duplicate start replaced worker'
ubus call service list '{"name":"candy-platform-probe"}' >"$evidence/services-before.json"

rm -f "$root/worker-ready.pid"
kill -KILL "$worker_before"
wait_ready
worker_recovered=$(pid worker)
[ "$worker_recovered" != "$worker_before" ] || fail 'SIGKILL worker did not restart'
[ "$(pid infrastructure)" = "$infrastructure_before" ] || fail 'worker crash restarted infrastructure'

kill -KILL "$infrastructure_before"
i=0
while [ "$i" -lt 20 ]; do
    infrastructure_recovered=$(pid infrastructure)
    [ -n "$infrastructure_recovered" ] && [ "$infrastructure_recovered" != "$infrastructure_before" ] && break
    i=$((i + 1)); sleep 1
done
[ "$i" -lt 20 ] || fail 'infrastructure SIGKILL did not restart'
[ "$(pid worker)" = "$worker_recovered" ] || fail 'infrastructure restart cascaded to worker'

# Reset the test instance counters before measuring the persistent-fault burst.
stop_probe
rm -f "$root/worker-ready.pid"
/etc/init.d/candy-platform-probe start
wait_ready
infrastructure_recovered=$(pid infrastructure)
worker_recovered=$(pid worker)
touch "$root/fault"
rm -f "$root/worker-ready.pid"
attempts_before=$(wc -l <"$root/attempts")
kill -KILL "$worker_recovered"
sleep 8
attempts_after=$(wc -l <"$root/attempts")
[ "$attempts_after" -gt "$attempts_before" ] || fail 'fault retries were not exercised'
[ "$((attempts_after - attempts_before))" -le 4 ] || fail 'persistent fault exceeded procd retry bound'
sleep 3
[ "$(wc -l <"$root/attempts")" -eq "$attempts_after" ] || fail 'persistent fault continued restarting'
[ "$(pid infrastructure)" = "$infrastructure_recovered" ] || fail 'fault spread to infrastructure'
cp "$root/attempts" "$evidence/attempts.log"
rm "$root/fault"
stop_probe
rm -f "$root/worker-ready.pid"
/etc/init.d/candy-platform-probe start
wait_ready
ubus call service list '{"name":"candy-platform-probe"}' >"$evidence/services-after.json"
logread >"$evidence/logread.log"
protocol_probe=NOT_RUN
if [ "$real_netd" = true ]; then
    i=0
    while [ "$i" -lt 3 ]; do
        "$root/candy-netd" --probe-socket "$root/netd.sock" --probe-protocol v2 || fail 'protocol-v2 probe failed'
        i=$((i + 1))
    done
    logread >"$evidence/logread.log"
    if grep -q 'code=netd_v2_request_failed' "$evidence/logread.log"; then
        fail 'health checks produced netd request warnings'
    fi
    protocol_probe=PASS
fi
kernel_tun_test=NOT_RUN
if [ -f "$root/kernel-test" ]; then
    echo 'stage=official_offline_packages'
    # OpenWrt authenticates package digests through signed repository indexes.
    apk --no-network --repositories-file /dev/null \
        --repository "$root/repos/base/packages.adb" --repository "$root/repos/kmods/packages.adb" \
        add ip-full kmod-tun >"$evidence/apk-install.log" 2>&1
    modprobe tun
    test -c /dev/net/tun || fail 'official tun module did not expose /dev/net/tun'
    echo 'stage=real_linux_tun_kernel_test'
    chmod 755 "$root/kernel-test"
    CANDY_NETD_ISOLATED_KERNEL_TEST=1 "$root/kernel-test" \
        --exact real_linux_tun_survives_forward_revoke_and_netd_restart --ignored --nocapture \
        >"$evidence/kernel-tun-test.log" 2>&1
    grep -q '1 passed; 0 failed;' "$evidence/kernel-tun-test.log" || fail 'kernel test did not execute exactly one successful test'
    kernel_tun_test=PASS
fi
cat >"$evidence/result.json" <<EOF
{"pid1":"procd","openwrt":"$(. /etc/openwrt_release; echo "$DISTRIB_RELEASE")","real_netd":$real_netd,"worker_payload":"lifecycle_probe","duplicate_start_idempotent":true,"worker_sigkill_recovered":true,"worker_failure_preserves_infrastructure":true,"infrastructure_sigkill_recovered":true,"infrastructure_restart_preserves_worker":true,"persistent_fault_bounded":true,"fault_attempts":$((attempts_after - attempts_before)),"manual_recovery_after_fault":true,"protocol_v2_health_probe":"$protocol_probe","kernel_tun_guard_and_journal_recovery":"$kernel_tun_test","whole_platform":"NOT_RUN"}
EOF
/etc/init.d/candy-platform-probe stop
echo 'PASS narrow real procd lifecycle gate; full SD-WAN platform NOT RUN'
