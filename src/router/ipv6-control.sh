#!/bin/sh
# A trial lives only in RAM. USB changes only after an explicit confirmation.
set -eu
umask 077
ROOT=/tmp/okopy-router-ipv6
BASE=/opt/okopy-router-ipv6
EDIT=/tmp/okopy-router-ipv6-edit
LD="$ROOT/opt/lib/ld.so.1"; LIB="$ROOT/opt/lib"; BB="$ROOT/opt/bin/busybox"
bb() { "$LD" --library-path "$LIB" "$BB" "$@"; }
bounded() { "$LD" --library-path "$LIB" "$ROOT/opt/libexec/timeout-coreutils" --foreground -k 1 3 "$@"; }
error() { printf '{"error":"%s"}\n' "$1"; exit 0; }
stamp() { read -r uptime rest < /proc/uptime; now=${uptime%%.*}; }
hex() { [ "${#1}" = "$2" ] && case "$1" in *[!0-9a-f]*) return 1;; esac; }
put_status() { printf '%s\n' "$1" > "$EDIT/status.next"; bb mv "$EDIT/status.next" "$EDIT/status"; }
alive() {
 [ -r "$ROOT/state/service.pid" ] || return 1
 pid=$(bb cat "$ROOT/state/service.pid")
 case "$pid" in ''|*[!0-9]*) return 1;; esac
 [ -r "/proc/$pid/cmdline" ] && bb grep -q "$ROOT/ipv6-service.sh" "/proc/$pid/cmdline"
}
stop_service() {
 : > "$ROOT/state/service.stop"; : > "$ROOT/state/stop"
 n=0
 while alive; do n=$((n+1)); [ "$n" -le 24 ] || return 1; bb sleep 1; done
 [ ! -d "$ROOT/state/supervisor.lock" ]
}
start_service() {
 [ ! -d "$ROOT/state/supervisor.lock" ] || return 1
 bb rm -f "$ROOT/state/service.stop" "$ROOT/state/stop"
 bb start-stop-daemon -S -b -m -p "$ROOT/state/service.pid" -O "$ROOT/state/service.log" -x "$LD" -- --library-path "$LIB" "$BB" sh "$ROOT/ipv6-service.sh" "$ROOT"
 n=0
 while ! alive; do n=$((n+1)); [ "$n" -le 5 ] || return 1; bb sleep 1; done
}
lock() {
 bb mkdir -p "$EDIT"
 if ! bb mkdir "$EDIT/lock" 2>/dev/null; then
  owner=$(bb cat "$EDIT/lock/pid" 2>/dev/null || true)
  case "$owner" in ''|*[!0-9]*) error busy;; esac
  # Only a dead writer's lock can be recovered. Never race a live writer.
  if [ -d "/proc/$owner" ]; then error busy; fi
  bb rm -f "$EDIT/lock/pid"; bb rmdir "$EDIT/lock" || error busy
  bb mkdir "$EDIT/lock" || error busy
 fi
 printf '%s\n' "$$" > "$EDIT/lock/pid"
 trap 'bb rm -f "$EDIT/lock/pid"; bb rmdir "$EDIT/lock"' EXIT
 trap 'exit 74' HUP INT TERM
}
restore() {
 # A completed USB rename proves that confirm was requested and committed.
 if bounded "$LD" --library-path "$LIB" "$BB" cmp -s "$BASE/ipv6-settings.sh" "$EDIT/new.sh"; then
  put_status confirmed; return 0
 fi
 stop_service || { put_status rollback_failed; return 1; }
 bb cp "$EDIT/old.sh" "$ROOT/ipv6-settings.next"
 bb mv "$ROOT/ipv6-settings.next" "$ROOT/ipv6-settings.sh"
 start_service || { put_status rollback_failed; return 1; }
 put_status rolled_back
}
case "${1:-}" in
 inventory)
  printf '{"interfaces":'
  "$LD" --library-path "$LIB" "$ROOT/opt/bin/curl" --noproxy '*' --fail --silent --connect-timeout 1 --max-time 2 http://127.0.0.1:79/rci/show/interface
  printf ',"policies":'
  "$LD" --library-path "$LIB" "$ROOT/opt/bin/curl" --noproxy '*' --fail --silent --connect-timeout 1 --max-time 2 http://127.0.0.1:79/rci/show/ip/policy
  printf '}\n'
  ;;
 watch)
  [ "$#" = 2 ] && hex "$2" 32 || exit 64
  watched=$2
  while [ "$(bb cat "$EDIT/id" 2>/dev/null)" = "$watched" ] && [ "$(bb cat "$EDIT/status" 2>/dev/null)" = pending ]; do
   stamp; deadline=$(bb cat "$EDIT/deadline")
   [ "$now" -lt "$deadline" ] || bb sh "$ROOT/ipv6-control.sh" rollback "$watched"
   bb sleep 1
  done
  ;;
 status)
  lock
  . "$ROOT/ipv6-settings.sh"
  durable=false
  if bounded "$LD" --library-path "$LIB" "$BB" cmp -s "$ROOT/ipv6-settings.sh" "$BASE/ipv6-settings.sh"; then durable=true; fi
  controller=stopped; path=unknown
  if alive; then
   controller=stale; stamp; tick=$(bb cat "$ROOT/state/worker.tick" 2>/dev/null || true)
   case "$tick" in ''|*[!0-9]*) ;; *)
    epoch=''; read -r epoch ignored < "$ROOT/state/decision" || true
    if [ "$epoch" = "$REVISION" ] && [ "$tick" -le "$now" ] && [ "$((now-tick))" -lt 15 ] && [ "$(bb cat "$ROOT/state/supervisor.status" 2>/dev/null)" = watching ]; then controller=running; fi;;
   esac
  fi
  if bb sh "$ROOT/ipv6-routes.sh" "$ROOT" "$ROOT" check home >/dev/null 2>&1; then path=home
  elif bb sh "$ROOT/ipv6-routes.sh" "$ROOT" "$ROOT" check provider >/dev/null 2>&1; then path=provider; fi
  printf '{"settings":%s,"revision":"%s","persistent_matches":%s,"controller":"%s","path":"%s","transaction":' "$SETTINGS_JSON" "$REVISION" "$durable" "$controller" "$path"
  if [ -r "$EDIT/id" ]; then
   stamp; remaining=$(($(bb cat "$EDIT/deadline")-now)); [ "$remaining" -ge 0 ] || remaining=0
   [ "$remaining" -le 120 ] || remaining=120
   printf '{"id":"%s","status":"%s","remaining_seconds":%s}' "$(bb cat "$EDIT/id")" "$(bb cat "$EDIT/status")" "$remaining"
  else printf null; fi
  printf '}\n'
  ;;
 apply)
  [ "$#" = 5 ] && hex "$2" 64 && hex "$3" 64 && hex "$4" 64 && hex "$5" 32 || exit 64
  expected=$2; content_sha=$3; new_revision=$4; tx=$5
  [ "$expected" != "$new_revision" ] || error unchanged
  IFS= read -r -t 5 payload || error payload
  [ "${#payload}" -le 24000 ] || error payload
  lock
  case "$(bb cat "$EDIT/status" 2>/dev/null || true)" in pending|rollback_failed) error pending;; esac
  . "$ROOT/ipv6-settings.sh"
  [ "$REVISION" = "$expected" ] || error conflict
  bounded "$LD" --library-path "$LIB" "$BB" cmp -s "$ROOT/ipv6-settings.sh" "$BASE/ipv6-settings.sh" || error persist
  printf '%s' "$payload" | bb base64 -d > "$EDIT/new.sh" || error payload
  actual=$(bb sha256sum "$EDIT/new.sh"); actual=${actual%% *}
  [ "$actual" = "$content_sha" ] || error payload
  . "$EDIT/new.sh"
  [ "$REVISION" = "$new_revision" ] || error payload
  # Read-only validation against the selected policy's actual native ISP base.
  bb mkdir -p "$EDIT/check/state"
  bb cp "$EDIT/new.sh" "$EDIT/check/ipv6-settings.sh"
  bb sh "$ROOT/ipv6-routes.sh" "$EDIT/check" "$ROOT" check provider >/dev/null 2>&1 || error baseline
  bb cp "$ROOT/ipv6-settings.sh" "$EDIT/old.sh"
  printf '%s\n' "$tx" > "$EDIT/id"; stamp; printf '%s\n' "$((now+120))" > "$EDIT/deadline"
  put_status pending
  bb start-stop-daemon -S -b -m -p "$EDIT/guard-$tx.pid" -O "$EDIT/guard.log" -x "$LD" -- --library-path "$LIB" "$BB" sh "$ROOT/ipv6-control.sh" watch "$tx"
  bb sleep 1
  guard=$(bb cat "$EDIT/guard-$tx.pid"); bb kill -0 "$guard" || { put_status rolled_back; error start; }
  if ! stop_service; then error stop; fi
  bb cp "$EDIT/new.sh" "$ROOT/ipv6-settings.next"
  bb mv "$ROOT/ipv6-settings.next" "$ROOT/ipv6-settings.sh"
  if ! start_service; then restore || true; error start; fi
  printf '{"applied":true}\n'
  ;;
 confirm|rollback)
  [ "$#" = 2 ] && hex "$2" 32 || exit 64
  action=$1; tx=$2; lock
  [ "$(bb cat "$EDIT/id" 2>/dev/null)" = "$tx" ] || error transaction
  current=$(bb cat "$EDIT/status")
  if [ "$action:$current" = confirm:confirmed ] || [ "$action:$current" = rollback:rolled_back ]; then printf '{"done":true}\n'; exit; fi
  case "$current" in pending|rollback_failed) ;; *) error transaction;; esac
  if [ "$action" = rollback ]; then restore || error start
  else
   stamp; [ "$now" -lt "$(bb cat "$EDIT/deadline")" ] || error expired
   if bounded "$LD" --library-path "$LIB" "$BB" cmp -s "$BASE/ipv6-settings.sh" "$EDIT/new.sh"; then
    put_status confirmed; printf '{"done":true}\n'; exit
   fi
   bounded "$LD" --library-path "$LIB" "$BB" cmp -s "$BASE/ipv6-settings.sh" "$EDIT/old.sh" || error conflict
   [ "$current" = pending ] && alive || error start
   [ "$(bb cat "$ROOT/state/supervisor.status" 2>/dev/null)" = watching ] || error start
   bb cmp -s "$ROOT/ipv6-settings.sh" "$EDIT/new.sh" || error conflict
   . "$ROOT/ipv6-settings.sh"
   epoch=''; read -r epoch ignored < "$ROOT/state/decision" || true
   tick=$(bb cat "$ROOT/state/worker.tick" 2>/dev/null || true)
   case "$tick" in ''|*[!0-9]*) error start;; esac
   [ "$epoch" = "$REVISION" ] && [ "$tick" -le "$now" ] && [ "$((now-tick))" -lt 15 ] || error start
   bounded "$LD" --library-path "$LIB" "$BB" cp "$EDIT/new.sh" "$BASE/ipv6-settings.next" || error persist
   bounded "$LD" --library-path "$LIB" "$BB" fsync "$BASE/ipv6-settings.next" || error persist
   bounded "$LD" --library-path "$LIB" "$BB" mv "$BASE/ipv6-settings.next" "$BASE/ipv6-settings.sh" || error persist
   bounded "$LD" --library-path "$LIB" "$BB" fsync "$BASE" || error persist
   put_status confirmed
  fi
  printf '{"done":true}\n'
  ;;
 *) exit 64;;
esac
