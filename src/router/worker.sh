#!/bin/sh
# IPv4 pilot controller. The supervisor owns its whole process group.
set -eu
ROOT=$1; RUNTIME=$2
LD="$RUNTIME/opt/lib/ld.so.1"; LIB="$RUNTIME/opt/lib"; BB="$RUNTIME/opt/bin/busybox"
bb() { "$LD" --library-path "$LIB" "$BB" "$@"; }
pair() { "$LD" --library-path "$LIB" "$BB" sh "$ROOT/pair.sh" "$ROOT" "$RUNTIME" "$1"; }
. "$ROOT/pair-settings.sh"
: > "$ROOT/state/decision"
mode=provider
while :; do
    # Restore only our rules after NDM rewrites a table. Recovery starts in
    # provider mode and needs the same uninterrupted healthy interval again.
    if ! pair check; then
        read -r now rest < /proc/uptime
        printf '%s\tkernel-repair\n' "${now%%.*}" >> "$ROOT/state/transitions.tsv"
        pair repair || exit 1
        : > "$ROOT/state/decision"
        mode=provider
    fi
    rc=0
    "$LD" --library-path "$LIB" "$BB" sh "$ROOT/health.sh" "$RUNTIME" "$SERVER" 15454 15458 api.ipify.org https://api.ipify.org tsv > "$ROOT/state/sample.next" || rc=$?
    sample_state=unknown; sample_at=0; udp=unknown; tcp=unknown; https=unknown; http=0
    if [ "$rc" -le 1 ]; then read -r sample_state sample_at udp tcp https http < "$ROOT/state/sample.next" || true; fi
    read -r now rest < /proc/uptime; now=${now%%.*}
    bb awk -v epoch="$REVISION" -v now="$now" -v sample_at="$sample_at" -v sample_state="$sample_state" -v requested=auto -v integrity=1 -v failures_limit=3 -v recovery_seconds=60 -v max_age=15 -f "$ROOT/decision.awk" "$ROOT/state/decision" > "$ROOT/state/decision.next"
    read -r epoch next_mode rest < "$ROOT/state/decision.next"
    case "$next_mode" in provider|home) ;; *) exit 1;; esac
    if [ "$next_mode" != "$mode" ]; then
        pair "$next_mode"
        printf '%s\t%s\n' "$now" "$next_mode" >> "$ROOT/state/transitions.tsv"
        mode=$next_mode
    fi
    bb mv "$ROOT/state/decision.next" "$ROOT/state/decision"
    # Only complete iterations renew the lease observed by supervisor.
    read -r now rest < /proc/uptime; now=${now%%.*}
    printf '%s\n' "$now" > "$ROOT/state/tick.next"
    bb mv "$ROOT/state/tick.next" "$ROOT/state/worker.tick"
    bb sleep 3
done
