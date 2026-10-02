#!/bin/sh
# /opt is required only when starting or rebuilding the RAM runtime.
set -eu
BASE=/opt/okopy-router-monitor
ROOT=/tmp/okopy-router-monitor
BB=/opt/bin/busybox
pid_alive() {
    [ -f "$ROOT/state/pid" ] || return 1
    pid=$("$BB" cat "$ROOT/state/pid")
    case "$pid" in ''|*[!0-9]*) return 1;; esac
    [ -r "/proc/$pid/cmdline" ] && "$BB" grep -q "$ROOT/monitor.sh" "/proc/$pid/cmdline"
}
case "${1:-}" in
    start)
        if pid_alive; then exit 0; fi
        "$BB" mkdir /tmp/okopy-router-monitor-start.lock || exit 1
        STAGE="$ROOT.next.$$"
        trap '"$BB" rm -rf "$STAGE"; "$BB" rmdir /tmp/okopy-router-monitor-start.lock' EXIT
        trap 'exit 74' HUP INT TERM
        "$BB" mkdir -m 700 "$STAGE"
        "$BB" mkdir -p "$STAGE/tmp" "$STAGE/state"
        while IFS= read -r source; do
            case "$source" in /opt/lib/*|/opt/bin/busybox|/opt/bin/dig|/opt/bin/curl|/opt/etc/ssl/certs/ca-certificates.crt) ;; *) exit 1;; esac
            "$BB" mkdir -p "$STAGE$("$BB" dirname "$source")"
            "$BB" cp -L "$source" "$STAGE$source"
        done < "$BASE/runtime-files.txt"
        for name in health.sh monitor.sh settings.sh settings-control.sh; do "$BB" cp "$BASE/$name" "$STAGE/$name"; done
        "$BB" cp "$STAGE/settings.sh" "$STAGE/state/persisted-settings.sh"
        "$BB" chmod -R go-rwx "$STAGE"
        # Never replace a runtime underneath a live owner.
        if pid_alive; then exit 1; fi
        "$BB" rm -rf "$ROOT"
        "$BB" mv "$STAGE" "$ROOT"
        "$BB" start-stop-daemon -S -b -m -p "$ROOT/state/pid" -O "$ROOT/state/service.log" -x "$ROOT/opt/lib/ld.so.1" -- --library-path "$ROOT/opt/lib" "$ROOT/opt/bin/busybox" sh "$ROOT/monitor.sh"
        ;;
    stop)
        if pid_alive; then
            kill "$pid"
            attempt=0
            while pid_alive && [ "$attempt" -lt 7 ]; do "$BB" sleep 1; attempt=$((attempt+1)); done
            if pid_alive; then exit 1; fi
        fi
        ;;
    status|check) pid_alive;;
    restart)
        # Do not stop a working monitor when another start already owns staging.
        [ ! -d /tmp/okopy-router-monitor-start.lock ] || exit 1
        "$0" stop; "$0" start;;
    *) printf 'Usage: %s start|stop|restart|status\n' "$0" >&2; exit 64;;
esac
