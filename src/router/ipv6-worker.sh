#!/bin/sh
# Reuse the existing decision engine and supervisor. No domain rules here.
set -eu
ROOT=$1; RUNTIME=$2
LD="$RUNTIME/opt/lib/ld.so.1"; LIB="$RUNTIME/opt/lib"; BB="$RUNTIME/opt/bin/busybox"
bb() { "$LD" --library-path "$LIB" "$BB" "$@"; }
routes() { bb sh "$ROOT/ipv6-routes.sh" "$ROOT" "$RUNTIME" "$@"; }
tick() {
    read -r now rest < /proc/uptime
    printf '%s\n' "${now%%.*}" > "$ROOT/state/tick.next"
    bb mv "$ROOT/state/tick.next" "$ROOT/state/worker.tick"
}
. "$ROOT/ipv6-settings.sh"
routes provider
: > "$ROOT/state/decision"
mode=provider
while :; do
    if ! routes check "$mode"; then
        routes provider
        : > "$ROOT/state/decision"
        mode=provider
        # NDM can briefly remove/recreate the named policy. Stay on the saved
        # ISP base and retry discovery; an API gap cannot count as recovery.
        if ! routes check provider; then
            tick
            bb sleep "$INTERVAL_SECONDS"
            continue
        fi
    fi
    sample_state=down
    # The gate closes each accepted socket. Bound both a failed connect and a
    # stuck listener, without creating a process group outside our supervisor.
    if "$LD" --library-path "$LIB" "$RUNTIME/opt/libexec/timeout-coreutils" --foreground -k 1 "$PROBE_SECONDS" \
        "$LD" --library-path "$LIB" "$BB" nc "$HEALTH_ADDRESS" "$HEALTH_PORT" </dev/null >/dev/null 2>&1; then sample_state=up; fi
    read -r now rest < /proc/uptime; now=${now%%.*}
    bb awk -v epoch="$REVISION" -v now="$now" -v sample_at="$now" -v sample_state="$sample_state" \
        -v requested=auto -v integrity=1 -v failures_limit="$FAILURES" -v recovery_seconds="$RECOVERY_SECONDS" \
        -v max_age=12 -f "$ROOT/decision.awk" "$ROOT/state/decision" > "$ROOT/state/decision.next"
    read -r epoch next_mode rest < "$ROOT/state/decision.next"
    case "$next_mode" in home|provider) ;; *) exit 1;; esac
    if [ "$next_mode" != "$mode" ]; then
        routes "$next_mode"
        printf '%s\t%s\n' "$now" "$next_mode" >> "$ROOT/state/transitions.tsv"
        mode=$next_mode
    fi
    bb mv "$ROOT/state/decision.next" "$ROOT/state/decision"
    tick
    bb sleep "$INTERVAL_SECONDS"
done
