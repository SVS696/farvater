#!/bin/sh
# One controller lifetime. Kill its whole process group before restoring ISP.
# worker.sh must atomically replace state/worker.tick with /proc/uptime seconds
# after each completed iteration. fallback.sh removes only this controller's rules.
# Neither script may daemonize or create a separate process group.
set -u
[ "$#" = 2 ] || exit 64
ROOT=${1%/}; RUNTIME=${2%/}
case "$ROOT:$RUNTIME" in *[!a-zA-Z0-9_./:-]*|*..*) exit 64;; esac
case "$ROOT" in /tmp/okopy-*) ;; *) exit 64;; esac
case "$RUNTIME" in /tmp/okopy-*) ;; *) exit 64;; esac
LD="$RUNTIME/opt/lib/ld.so.1"; LIB="$RUNTIME/opt/lib"; BB="$RUNTIME/opt/bin/busybox"
TIMEOUT="$RUNTIME/opt/libexec/timeout-coreutils"
bb() { "$LD" --library-path "$LIB" "$BB" "$@"; }
stamp() { read -r now rest < /proc/uptime; now=${now%%.*}; }
status() { printf '%s\n' "$1" > "$ROOT/state/supervisor.next"; bb mv "$ROOT/state/supervisor.next" "$ROOT/state/supervisor.status"; }
# A second supervisor must never become another owner of the same rules.
bb mkdir "$ROOT/state/supervisor.lock" || exit 73
printf '%s\n' "$$" > "$ROOT/state/supervisor.lock/pid"
leader=''; reason=starting
group_alive() {
    # /proc entries may disappear during this scan. A vanished unrelated PID
    # must not abort the scan before reaching a still-running writer.
    for proc in /proc/[0-9]*/stat; do
        entry=''
        { IFS= read -r entry < "$proc"; } 2>/dev/null || continue
        entry=${entry##*) }
        set -- $entry
        if [ "$3" = "$leader" ] && [ "$1" != Z ] && [ "$1" != X ]; then return 0; fi
    done
    return 1
}
finish() {
    trap '' HUP INT TERM
    if [ -n "$leader" ]; then
        # timeout created this group; all network writers are in it.
        bb kill -KILL "-$leader" 2>/dev/null || true
        bb kill -KILL "$leader" 2>/dev/null || true
        wait "$leader" 2>/dev/null || true
        bb kill -KILL "-$leader" 2>/dev/null || true
        # Refuse a concurrent cleanup if a writer is still executing in kernel.
        tries=0
        while group_alive; do
            tries=$((tries+1))
            if [ "$tries" -ge 3 ]; then status writer-still-running; return 1; fi
            bb sleep 1
        done
    fi
    # A blocked cleanup is bounded too. Its children share this timeout group.
    "$LD" --library-path "$LIB" "$TIMEOUT" -k 1 5 "$LD" --library-path "$LIB" "$BB" sh "$ROOT/fallback.sh" "$ROOT" "$RUNTIME" > "$ROOT/state/fallback.log" 2>&1
    rc=$?
    if [ "$rc" != 0 ]; then status "fallback-failed:$rc:$reason"; return 1; fi
    status "provider:$reason"
    bb rm -f "$ROOT/state/supervisor.lock/pid"
    bb rmdir "$ROOT/state/supervisor.lock"
}
trap 'reason=stopped; finish; exit $?' HUP INT TERM
[ -x "$TIMEOUT" ] && [ -r "$ROOT/worker.sh" ] && [ -r "$ROOT/fallback.sh" ] || { status missing-runtime; exit 69; }
bb rm -f "$ROOT/state/worker.tick"
stamp; started=$now
"$LD" --library-path "$LIB" "$TIMEOUT" 0 "$LD" --library-path "$LIB" "$BB" sh "$ROOT/worker.sh" "$ROOT" "$RUNTIME" > "$ROOT/state/worker.log" 2>&1 &
leader=$!
printf '%s\n' "$leader" > "$ROOT/state/group.pid"
status watching
while :; do
    stamp
    if ! bb kill -0 "$leader" 2>/dev/null; then reason=worker-exited; break; fi
    if [ -f "$ROOT/state/stop" ]; then reason=stopped; break; fi
    tick=''; extra=''
    if [ -f "$ROOT/state/worker.tick" ]; then
        read -r tick extra < "$ROOT/state/worker.tick" || true
        case "$tick" in ''|*[!0-9]*) reason=invalid-heartbeat; break;; esac
        if [ "${#tick}" -gt 10 ] || [ -n "$extra" ] || [ "$tick" -gt "$now" ] || [ "$tick" -lt "$started" ]; then reason=invalid-heartbeat; break; fi
    else tick=$started
    fi
    if [ "$((now-tick))" -ge 15 ]; then reason=stale-heartbeat; break; fi
    bb sleep 1
done
finish
