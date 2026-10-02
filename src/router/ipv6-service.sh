#!/bin/sh
# Restart a cleanly recovered worker; retain evidence after an unsafe cleanup.
set -u
ROOT=$1
LD="$ROOT/opt/lib/ld.so.1"; LIB="$ROOT/opt/lib"; BB="$ROOT/opt/bin/busybox"
bb() { "$LD" --library-path "$LIB" "$BB" "$@"; }
stop() { : > "$ROOT/state/service.stop"; : > "$ROOT/state/stop"; }
trap stop HUP INT TERM
while [ ! -f "$ROOT/state/service.stop" ]; do
    bb rm -f "$ROOT/state/stop"
    printf '%s\n' running > "$ROOT/state/service.status"
    bb sh "$ROOT/supervise.sh" "$ROOT" "$ROOT" &
    supervisor=$!
    printf '%s\n' "$supervisor" > "$ROOT/state/supervisor.pid"
    wait "$supervisor"
    # A signal can interrupt wait before the supervisor has cleaned its worker.
    while bb kill -0 "$supervisor" 2>/dev/null; do bb sleep 1; done
    status=$(bb cat "$ROOT/state/supervisor.status" 2>/dev/null)
    case "$status" in provider:*) ;; *) printf '%s\n' needs-attention > "$ROOT/state/service.status"; exit 1;; esac
    [ ! -d "$ROOT/state/supervisor.lock" ] || exit 1
    [ ! -f "$ROOT/state/service.stop" ] || break
    printf '%s\n' restarting > "$ROOT/state/service.status"
    bb sleep 5
done
printf '%s\n' stopped > "$ROOT/state/service.status"
