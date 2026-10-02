#!/bin/sh
# RAM-only, read-only router measurements. Does not change routes or services.
set -u
ROOT=/tmp/okopy-router-monitor
LD="$ROOT/opt/lib/ld.so.1"
LIB="$ROOT/opt/lib"
BB="$ROOT/opt/bin/busybox"
bb() { "$LD" --library-path "$LIB" "$BB" "$@"; }
trap 'exit 0' HUP INT TERM
while :; do
    # settings.sh is generated from typed parameters, owned by root and replaced atomically.
    . "$ROOT/settings.sh"
    "$LD" --library-path "$LIB" "$BB" sh "$ROOT/health.sh" "$ROOT" "$SERVER" "$DNS_PORT" "$PROXY_PORT" "$DOMAIN" "$URL" > "$ROOT/state/next" 2> "$ROOT/state/last-error"
    code=$?
    if [ "$code" -gt 1 ] || ! bb grep -Eq '^\{"status":"(up|down)"' "$ROOT/state/next"; then
        printf '{"status":"unknown","observed_at":%s,"uptime_seconds":0,"dns_udp":"unknown","dns_tcp":"unknown","https":"unknown","http_code":0}\n' "$(bb date +%s)" > "$ROOT/state/next"
    fi
    # Bind the measurement to the parameters used at its start.
    measurement=$(bb cat "$ROOT/state/next")
    # Keep transitions at the source: a failure/recovery between SSH polls must remain visible.
    # Ignore timestamps when comparing outcomes; records are bounded and stay in RAM.
    outcome=$(printf '%s\n' "$measurement" | bb sed -E 's/"observed_at":[0-9]+/"observed_at":0/; s/"uptime_seconds":[0-9]+/"uptime_seconds":0/')
    key="$REVISION:$outcome"
    if [ "$key" != "$(bb cat "$ROOT/state/history-key" 2>/dev/null)" ]; then
        { bb tail -n 9 "$ROOT/state/history.jsonl" 2>/dev/null || true
          printf '{"revision":"%s","measurement":%s}\n' "$REVISION" "$measurement"
        } > "$ROOT/state/history.next"
        bb mv "$ROOT/state/history.next" "$ROOT/state/history.jsonl"
        printf '%s\n' "$key" > "$ROOT/state/history-key"
    fi
    history=$(bb awk 'BEGIN {printf "["} NR>1 {printf ","} {printf "%s", $0} END {printf "]"}' "$ROOT/state/history.jsonl")
    printf '{"version":2,"revision":"%s","measurement":%s,"history":%s}\n' "$REVISION" "$measurement" "$history" > "$ROOT/state/ready"
    bb mv "$ROOT/state/ready" "$ROOT/state/health.json"
    "$LD" --library-path "$LIB" "$BB" sleep 5
 done
