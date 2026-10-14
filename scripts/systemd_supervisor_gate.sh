#!/usr/bin/env bash
set -Eeuo pipefail

# Real systemd PID1 gate in an isolated Docker container. Fake payloads keep
# this test independent of Cloud, Core and production TUN devices.
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=${CANDY_SYSTEMD_GATE_IMAGE:-candy-sdwan-systemd-gate:bookworm}
container=${CANDY_SYSTEMD_GATE_CONTAINER:-candy-sdwan-systemd-gate-$$}
report=${CANDY_SYSTEMD_GATE_REPORT:-}
die() { printf 'systemd_supervisor_gate: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null || die "docker is required"
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"
if ! docker image inspect "$image" >/dev/null 2>&1; then
  build_dir=$(mktemp -d)
  trap 'rm -rf "$build_dir"' EXIT
  cat >"$build_dir/Dockerfile" <<'EOF'
FROM debian:bookworm-slim
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
EOF
  docker build -t "$image" "$build_dir" >/dev/null || die "failed to build systemd gate image"
fi
docker rm -f "$container" >/dev/null 2>&1 || true
docker run -d --name "$container" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$image" /sbin/init >/dev/null || die "failed to start systemd container"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
state=unknown
for _ in $(seq 1 30); do
  state=$(docker exec "$container" systemctl is-system-running 2>/dev/null || true)
  [ "$state" = running ] && break
  sleep 1
done
[ "$state" = running ] || die "systemd did not reach running state: $state"
docker exec "$container" sh -eu -c '
  useradd --system --home /var/lib/candy/sdwan --create-home candy-sdwan 2>/dev/null || true
  mkdir -p /usr/local/libexec /run/candy /run/candy-netd /run/candy-gate /var/lib/candy/sdwan/activations
  chmod 0777 /run/candy-gate
  aid=$(printf "a%.0s" $(seq 1 64)); mkdir -p "/var/lib/candy/sdwan/activations/$aid"; ln -sfn "activations/$aid" /var/lib/candy/sdwan/candidate
  chown -R candy-sdwan:candy-sdwan /var/lib/candy/sdwan /run/candy
  printf "%s\n" "#!/bin/sh" "echo start pid=\$\$ >>/run/candy-gate/netd.log" "trap \"echo stop pid=\$\$ >>/run/candy-gate/netd.log; exit 0\" TERM INT" "while :; do sleep 1; done" >/usr/local/libexec/candy-netd-gate
  printf "%s\n" "#!/bin/sh" "echo start pid=\$\$ >>/run/candy-gate/agent.log" "trap \"echo stop pid=\$\$ >>/run/candy-gate/agent.log; exit 0\" TERM INT" "while :; do sleep 1; done" >/usr/local/libexec/candy-agent-gate
  printf "%s\n" "#!/bin/sh" "echo recover >>/run/candy-gate/netd.log" >/usr/local/libexec/candy-netd-recover-gate
  printf "%s\n" "#!/bin/sh" "echo \"\$*\" >>/run/candy-gate/runtime.log" >/usr/local/libexec/candy-runtime-gate
  chmod +x /usr/local/libexec/candy-*-gate
'
docker cp "$repo_dir/linux/client/packaging/candy-netd.service" "$container:/etc/systemd/system/candy-netd.service"
docker cp "$repo_dir/linux/client/packaging/candy-sdwan.service" "$container:/etc/systemd/system/candy-sdwan.service"
docker exec "$container" sh -eu -c '
  mkdir -p /etc/systemd/system/candy-netd.service.d /etc/systemd/system/candy-sdwan.service.d
  cat >/etc/systemd/system/candy-netd.service.d/gate.conf <<"EOF"
[Service]
ExecStartPre=
ExecStart=
ExecStart=/usr/local/libexec/candy-netd-gate
ExecStopPost=
ExecStopPost=+/usr/local/libexec/candy-netd-recover-gate
ProtectSystem=off
EOF
  cat >/etc/systemd/system/candy-sdwan.service.d/gate.conf <<"EOF"
[Service]
ExecStartPre=
ExecStartPre=/usr/local/libexec/candy-runtime-gate publish
ExecStart=
ExecStart=/usr/local/libexec/candy-agent-gate
ExecStopPost=
ExecStopPost=+/usr/local/libexec/candy-runtime-gate fail-open service-stopped
ProtectSystem=off
EOF
  systemctl daemon-reload; systemd-analyze verify /etc/systemd/system/candy-netd.service /etc/systemd/system/candy-sdwan.service
  systemctl reset-failed candy-netd.service candy-sdwan.service || true
  systemctl start candy-netd.service candy-sdwan.service; sleep 2
  test "$(systemctl is-active candy-netd.service)" = active; test "$(systemctl is-active candy-sdwan.service)" = active
'
netd_before=$(docker exec "$container" systemctl show candy-netd.service -p MainPID --value)
agent_before=$(docker exec "$container" systemctl show candy-sdwan.service -p MainPID --value)
docker exec "$container" systemctl restart candy-netd.service; sleep 2
netd_after=$(docker exec "$container" systemctl show candy-netd.service -p MainPID --value)
agent_after=$(docker exec "$container" systemctl show candy-sdwan.service -p MainPID --value)
[ "$netd_before" != "$netd_after" ] || die "netd PID did not change"
[ "$agent_before" = "$agent_after" ] || die "netd restart cascaded into Agent restart"
restarts_before=$(docker exec "$container" systemctl show candy-sdwan.service -p NRestarts --value)
docker exec "$container" sh -c "kill -KILL $agent_after"; active=inactive; agent_recovered=$agent_after
for _ in $(seq 1 20); do
  agent_recovered=$(docker exec "$container" systemctl show candy-sdwan.service -p MainPID --value)
  active=$(docker exec "$container" systemctl is-active candy-sdwan.service 2>/dev/null || true)
  [ "$active" = active ] && [ "$agent_recovered" != "$agent_after" ] && break
  sleep 1
done
restarts_after=$(docker exec "$container" systemctl show candy-sdwan.service -p NRestarts --value)
[ "$active" = active ] || die "Agent did not recover"
[ "$agent_recovered" != "$agent_after" ] || die "Agent PID did not change after SIGKILL"
[ "$restarts_after" -gt "$restarts_before" ] || die "NRestarts did not increase"
result=$(printf '{"pid1":"systemd","systemd_state":"running","netd_restart_isolated":true,"agent_crash_recovered":true,"netd_pid_before":%s,"netd_pid_after":%s,"agent_pid_before":%s,"agent_pid_after_netd_restart":%s,"agent_pid_after_sigkill":%s,"n_restarts_before":%s,"n_restarts_after":%s,"scope":"fake payloads in isolated Docker; no TUN/Cloud/production"}' "$netd_before" "$netd_after" "$agent_before" "$agent_after" "$agent_recovered" "$restarts_before" "$restarts_after")
printf '%s\n' "$result"
if [ -n "$report" ]; then mkdir -p "$(dirname "$report")"; printf '%s\n' "$result" >"$report"; fi
