# Xray-core Custom Patches

`vpn-ui` tracks upstream [`XTLS/Xray-core`](https://github.com/XTLS/Xray-core) cleanly at the pinned release tag in `third_party/Xray-core` (currently `v26.11.9`) and applies the custom patches in this directory sequentially during `build/core/build.sh` inside an isolated staging copy.

Because `third_party/Xray-core` remains unmodified on an upstream commit, future upgrades only need to advance the submodule/ref and rebase these patch files, while automated tests (`xray/patches_guard_test.go`) and `build/core/build.sh` guarantee none of these patches are silently dropped.

## Patch Set

| Order | File | Purpose |
| --- | --- | --- |
| 01 | `01-shadowsocks-cipher-fallback.patch` | Inherit server-level `method` for Shadowsocks users when per-user `cipher` is empty (`infra/conf/shadowsocks.go`). |
| 02 | `02-speedlimit-rate.patch` | Per-account upload/download bandwidth limiting via `XRAY_SPEEDLIMIT_FILE` across both dispatcher seams (`Dispatch`/`getLink` and `DispatchLink`/`WrapLink`) and IP/CIDR resolution for `dokodemo-door` (`common/speedlimit`, `app/dispatcher/default.go`). |
| 03 | `03-speedlimit-iplimit.patch` | Per-account concurrent source IP admission control and eviction (`reject`/`accept` strategies) via `XRAY_SPEEDLIMIT_FILE` (`common/speedlimit/iplimit.go`, `app/dispatcher/default.go`). |
| 04 | `04-speedlimit-disable-splice.patch` | Set `sessionInbound.CanSpliceCopy = 3` whenever a session is speed-limited so zero-copy splicing never bypasses `common/speedlimit` pacing wrappers. |
| 05 | `05-anytls-tuic-naive.patch` | Add native AnyTLS, TUIC v5, and NaiveProxy inbound/outbound implementations, restored `common/singbridge` adapter helpers, transport wiring, and distro registrations. |
| 06 | `06-legacy-reverse.patch` | Re-enable legacy `"reverse"` (`bridges`/`portals`) JSON config loading required by `web/html/settings/xray/reverse.html`. |

## Reproducing Locally

```bash
git -C third_party/Xray-core checkout v26.11.9
tmpdir="$(mktemp -d)"
cp -a third_party/Xray-core/. "$tmpdir/"
for p in patches/xray/*.patch; do
  git -C "$tmpdir" apply "$PWD/$p"
done
```
