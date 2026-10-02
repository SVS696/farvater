#!/bin/sh
# The saved native ISP routes remain usable without this USB service.
set -eu
BASE=/opt/okopy-router-ipv6
ROOT=/tmp/okopy-router-ipv6
BB=/opt/bin/busybox
alive() {
    [ -r "$ROOT/state/service.pid" ] || return 1
    pid=$("$BB" cat "$ROOT/state/service.pid")
    case "$pid" in ''|*[!0-9]*) return 1;; esac
    [ -r "/proc/$pid/cmdline" ] && "$BB" grep -q "$ROOT/ipv6-service.sh" "/proc/$pid/cmdline"
}
case "${1:-}" in
 start)
    if alive; then exit 0; fi
    "$BB" mkdir /tmp/okopy-router-ipv6-start.lock || exit 1
    STAGE="$ROOT.next.$$"
    trap '"$BB" rm -rf "$STAGE"; "$BB" rmdir /tmp/okopy-router-ipv6-start.lock' EXIT
    trap 'exit 74' HUP INT TERM
    # A crashed supervisor may still have a worker. Never replace its runtime.
    [ ! -d "$ROOT/state/supervisor.lock" ] || exit 1
    "$BB" mkdir -m 700 "$STAGE"
    "$BB" cp -RL "$BASE/runtime/opt" "$STAGE/opt"
    "$BB" mkdir "$STAGE/state"
    for name in supervise.sh decision.awk ipv6-routes.sh ipv6-settings.sh ipv6-service.sh ipv6-control.sh; do "$BB" cp "$BASE/$name" "$STAGE/$name"; done
    "$BB" cp "$BASE/ipv6-worker.sh" "$STAGE/worker.sh"
    "$BB" cp "$BASE/ipv6-fallback.sh" "$STAGE/fallback.sh"
    "$BB" chmod -R go-rwx "$STAGE"
    [ -z "$("$BB" find "$STAGE" -type l)" ] || exit 1
    if alive; then exit 1; fi
    "$BB" rm -rf "$ROOT"
    "$BB" mv "$STAGE" "$ROOT"
    "$BB" start-stop-daemon -S -b -m -p "$ROOT/state/service.pid" -O "$ROOT/state/service.log" -x "$ROOT/opt/lib/ld.so.1" -- --library-path "$ROOT/opt/lib" "$ROOT/opt/bin/busybox" sh "$ROOT/ipv6-service.sh" "$ROOT"
    ;;
 stop)
    if alive; then
        : > "$ROOT/state/service.stop"
        : > "$ROOT/state/stop"
        tries=0
        while alive && [ "$tries" -lt 12 ]; do "$BB" sleep 1; tries=$((tries+1)); done
        if alive; then exit 1; fi
    fi
    [ ! -d "$ROOT/state/supervisor.lock" ] || exit 1
    ;;
 restart) "$0" stop; "$0" start;;
 status|check) alive;;
 *) printf 'Usage: %s start|stop|restart|status\n' "$0" >&2; exit 64;;
esac
