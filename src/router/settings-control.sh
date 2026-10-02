#!/bin/sh
# Typed settings are compiled locally; this authenticated endpoint only commits bytes.
set -eu
umask 077
ROOT=/tmp/okopy-router-monitor
BASE=/opt/okopy-router-monitor
LD="$ROOT/opt/lib/ld.so.1"; LIB="$ROOT/opt/lib"; BB="$ROOT/opt/bin/busybox"
bb() { "$LD" --library-path "$LIB" "$BB" "$@"; }
error() { printf '{"error":"%s"}\n' "$1"; exit 0; }
lock_settings() {
 bb mkdir "$ROOT/state/settings.lock" || error busy
 NEXT="$ROOT/state/settings.next"
 trap 'bb rm -f "$NEXT"; bb rmdir "$ROOT/state/settings.lock"' EXIT
 trap 'exit 74' HUP INT TERM
}
case "${1:-}" in
 status|read)
  if [ "$1" = status ]; then lock_settings; fi
  . "$ROOT/settings.sh"
  durable=false
  if [ "$1" = read ]; then
   # Never touch USB during periodic reads: a hung block device must not hide RAM health.
   if bb cmp -s "$ROOT/settings.sh" "$ROOT/state/persisted-settings.sh"; then durable=true; fi
  elif bb cmp -s "$ROOT/settings.sh" "$BASE/settings.sh"; then
   durable=true
   bb cp "$ROOT/settings.sh" "$ROOT/state/persisted-settings.next"
   bb mv "$ROOT/state/persisted-settings.next" "$ROOT/state/persisted-settings.sh"
  else
   bb rm -f "$ROOT/state/persisted-settings.sh"
  fi
  if [ "$1" = read ]; then printf '{"settings":'; fi
  printf '{"check":%s,"revision":"%s","persistent_matches":%s}' "$SETTINGS_JSON" "$REVISION" "$durable"
  if [ "$1" = read ]; then
   printf ',"snapshot":'
   if [ -f "$ROOT/state/health.json" ]; then bb head -c 16385 "$ROOT/state/health.json"; else printf null; fi
   printf '}'
  fi
  printf '\n'
  ;;
 apply)
  [ "$#" -eq 3 ] || exit 64
  expected=$2; content_sha=$3
  [ "${#expected}" -eq 64 ] && [ "${#content_sha}" -eq 64 ] || exit 64
  case "$expected$content_sha" in *[!0-9a-f]*) exit 64;; esac
  IFS= read -r -t 5 payload || error payload
  [ "${#payload}" -le 24000 ] || error payload
  lock_settings
  printf '%s' "$payload" | bb base64 -d > "$NEXT" || error payload
  actual=$(bb sha256sum "$NEXT"); actual=${actual%% *}
  [ "$actual" = "$content_sha" ] || error payload
  . "$ROOT/settings.sh"
  [ "$REVISION" = "$expected" ] || { printf '{"error":"conflict"}\n'; exit 0; }
  # Invalidate the RAM receipt before storage I/O; failed/partial saves remain visible.
  bb rm -f "$ROOT/state/persisted-settings.sh"
  # Persistence first. If the RAM commit is interrupted, status exposes divergence.
  bb cp "$ROOT/settings.sh" "$BASE/settings.previous.sh" || error persist
  bb fsync "$BASE/settings.previous.sh" || error persist
  bb cp "$NEXT" "$BASE/settings.next.sh" || error persist
  bb fsync "$BASE/settings.next.sh" || error persist
  bb mv "$BASE/settings.next.sh" "$BASE/settings.sh"
  bb fsync "$BASE"
  bb mv "$NEXT" "$ROOT/settings.sh"
  bb cp "$ROOT/settings.sh" "$ROOT/state/persisted-settings.next"
  bb mv "$ROOT/state/persisted-settings.next" "$ROOT/state/persisted-settings.sh"
  . "$ROOT/settings.sh"
  printf '{"version":1,"revision":"%s","measurement":{"status":"unknown","observed_at":%s,"uptime_seconds":0,"dns_udp":"unknown","dns_tcp":"unknown","https":"unknown","http_code":0}}\n' "$REVISION" "$(bb date +%s)" > "$ROOT/state/invalidated"
  bb mv "$ROOT/state/invalidated" "$ROOT/state/health.json"
  printf '{"saved":true,"revision":"%s"}\n' "$REVISION"
  ;;
 *) exit 64;;
esac
