#!/bin/sh
set -eu

target=${1:-x86_64-unknown-linux-gnu}
case "$target" in
  x86_64-unknown-linux-*) artifact_arch=x86_64 ;;
  aarch64-unknown-linux-musl)
    artifact_arch=aarch64
    if [ -z "${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:-}" ]; then
      if command -v aarch64-linux-musl-gcc >/dev/null 2>&1; then
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc
      elif [ "$(uname -m)" = aarch64 ] && command -v musl-gcc >/dev/null 2>&1; then
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
      else
        printf '%s\n' "missing aarch64 musl linker; install aarch64-linux-musl-gcc or set CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER" >&2
        exit 2
      fi
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER
    fi
    ;;
  aarch64-unknown-linux-*) artifact_arch=aarch64 ;;
  *)
    printf '%s\n' "unsupported Linux release target: $target" >&2
    exit 1
    ;;
esac
cargo build --release --locked -p client-cli -p serverd-linux --target "$target"
cargo_target_dir=${CARGO_TARGET_DIR:-target}
client_bin="$cargo_target_dir/$target/release/client-cli"
server_bin="$cargo_target_dir/$target/release/serverd-linux"
if command -v file >/dev/null 2>&1; then
  for bin in "$client_bin" "$server_bin"; do
    if ! file "$bin" | grep -q 'ELF'; then
      printf '%s\n' "built artifact is not an ELF Linux binary: $bin" >&2
      exit 1
    fi
  done
fi
mkdir -p dist/linux/usr/local/bin dist/linux/etc/candy dist/linux/systemd
cp "$client_bin" dist/linux/usr/local/bin/client-cli
cp "$server_bin" dist/linux/usr/local/bin/serverd-linux
cp "$server_bin" "dist/linux/serverd-linux-$artifact_arch"
chmod 0755 "dist/linux/serverd-linux-$artifact_arch"
cp packaging/linux/client.example.toml dist/linux/etc/candy/client.toml.example
cp server.example.toml dist/linux/etc/candy/server.toml.example
cp packaging/linux/candy-client.service dist/linux/systemd/candy-client.service
cp packaging/linux/candy-server.service dist/linux/systemd/candy-server.service
printf '%s\n' "linux $artifact_arch client/server package staged in dist/linux"
