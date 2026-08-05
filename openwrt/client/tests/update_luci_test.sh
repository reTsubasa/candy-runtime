#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
controller=$root/packages/luci-app-candy/root/usr/lib/lua/luci/controller/candy_update.lua
view=$root/packages/luci-app-candy/root/usr/lib/lua/luci/view/candy/update.htm
po=$root/packages/luci-app-candy/po/zh-cn/candy.zh-cn.po

for file in "$controller" "$view" "$po"; do [ -s "$file" ]; done
grep -F 'template("candy/update")' "$controller" >/dev/null
grep -F 'REQUEST_METHOD") ~= "POST"' "$controller" >/dev/null
grep -F 'formvalue("token")' "$controller" >/dev/null
grep -F 'value:match("^v[%w_]+$")' "$controller" >/dev/null
grep -F '{ UPDATE_MANAGER, "check" }' "$controller" >/dev/null
grep -F '{ UPDATE_MANAGER, "install-core", version_key }' "$controller" >/dev/null
grep -F '{ UPDATE_MANAGER, "install-runtime", version_key }' "$controller" >/dev/null
! grep -Eq 'formvalue\("(url|sha256|path)"\)' "$controller"
grep -F 'candy-update-runtime' "$view" >/dev/null
grep -F 'candy-update-core' "$view" >/dev/null
grep -F 'setTimeout(refreshCandyUpdateStatus, 2000)' "$view" >/dev/null
grep -F 'never activated automatically' "$view" >/dev/null
grep -F 'Update checks and installations are manual' "$view" >/dev/null
grep -F 'msgid "Updates"' "$po" >/dev/null
grep -F 'msgstr "更新"' "$po" >/dev/null

printf '%s\n' "OpenWrt Candy update LuCI contract passed"
