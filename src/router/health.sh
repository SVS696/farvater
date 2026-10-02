#!/bin/sh
# Read-only measurement. Invoke with the copied BusyBox shell and RAM loader.
# Arguments: runtime root, server IPv4, DNS port, proxy port, DNS name, HTTPS URL.
set -u
[ "$#" -eq 6 ] || [ "$#" -eq 7 ] || exit 64
ROOT=${1%/}
SERVER=$2
DNS_PORT=$3
PROXY_PORT=$4
DOMAIN=$5
URL=$6
FORMAT=${7:-json}
case "$FORMAT" in json|tsv) ;; *) exit 64;; esac
LD="$ROOT/opt/lib/ld.so.1"
LIB="$ROOT/opt/lib"
BB="$ROOT/opt/bin/busybox"
runbb() { "$LD" --library-path "$LIB" "$BB" "$@"; }
# These values also pass the provisioning validator; reject shell/output hazards here.
case "$SERVER" in ''|*[!0-9.]*) exit 64;; esac
case "$DNS_PORT:$PROXY_PORT" in *[!0-9:]*) exit 64;; esac
case "$DOMAIN" in ''|*[!a-zA-Z0-9.-]*) exit 64;; esac
case "$URL" in https://*) ;; *) exit 64;; esac
WORK="$ROOT/tmp/health-$$"
runbb mkdir -m 700 "$WORK" || exit 70
trap 'runbb rm -rf "$WORK"' EXIT
# Limit the complete process, including dynamic loading and entropy initialization.
# The target is one external loader process: its PID survives exec into dig/curl.
bounded() {
    label=$1; limit=$2; shift 2
    "$LD" --library-path "$LIB" "$@" > "$WORK/$label.out" 2> "$WORK/$label.err" &
    target=$!
    (
        sleeper=''
        trap '[ -z "$sleeper" ] || { kill "$sleeper" 2>/dev/null; wait "$sleeper" 2>/dev/null; }; exit 0' HUP INT TERM
        "$LD" --library-path "$LIB" "$BB" sleep "$limit" &
        sleeper=$!
        wait "$sleeper"
        kill -KILL "$target" 2>/dev/null
    ) &
    guard=$!
    wait "$target"; result=$?
    kill "$guard" 2>/dev/null
    wait "$guard" 2>/dev/null
    printf '%s\n' "$result" > "$WORK/$label.rc"
}
bounded dns_udp 3 "$ROOT/opt/bin/dig" -r -4 "@$SERVER" -p "$DNS_PORT" "$DOMAIN" A +notcp +ignore +time=1 +tries=1 +noall +comments +answer &
UDP_PID=$!
bounded dns_tcp 3 "$ROOT/opt/bin/dig" -r -4 "@$SERVER" -p "$DNS_PORT" "$DOMAIN" A +tcp +time=1 +tries=1 +noall +comments +answer &
TCP_PID=$!
bounded https 5 "$ROOT/opt/bin/curl" --cacert "$ROOT/opt/etc/ssl/certs/ca-certificates.crt" --noproxy '' --proxy "socks5h://$SERVER:$PROXY_PORT" --connect-timeout 2 --max-time 4 --globoff --max-filesize 4096 --silent --show-error --output "$WORK/body" --write-out '%{http_code}' "$URL" &
HTTPS_PID=$!
wait "$UDP_PID"; wait "$TCP_PID"; wait "$HTTPS_PID"
dns_ok() {
    [ "$(runbb cat "$WORK/$1.rc")" = 0 ] || return 1
    # A valid refusal has process exit 0. Require success and a non-truncated answer.
    runbb awk '
      /status: NOERROR,/ {good=1}
      /^;; flags:/ {for(i=1;i<=NF;i++) if($i=="tc" || $i=="tc;") truncated=1}
      $3=="IN" && $4=="A" && $5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {answer=1}
      END {exit !(good && answer && !truncated)}' "$WORK/$1.out"
}
UDP=down; TCP=down; HTTPS=down
if dns_ok dns_udp; then UDP=up; fi
if dns_ok dns_tcp; then TCP=up; fi
HTTP_CODE=$(runbb cat "$WORK/https.out")
case "$HTTP_CODE" in 200|204) [ "$(runbb cat "$WORK/https.rc")" != 0 ] || HTTPS=up;; esac
case "$HTTP_CODE" in [1-5][0-9][0-9]) ;; *) HTTP_CODE=0;; esac
STATUS=down
[ "$UDP:$TCP:$HTTPS" != up:up:up ] || STATUS=up
read -r UPTIME REST < /proc/uptime
UPTIME=${UPTIME%%.*}
NOW=$(runbb date +%s)
if [ "$FORMAT" = tsv ]; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$STATUS" "$UPTIME" "$UDP" "$TCP" "$HTTPS" "$HTTP_CODE"
else
    printf '{"status":"%s","observed_at":%s,"uptime_seconds":%s,"dns_udp":"%s","dns_tcp":"%s","https":"%s","http_code":%s}\n' "$STATUS" "$NOW" "$UPTIME" "$UDP" "$TCP" "$HTTPS" "$HTTP_CODE"
fi
# A failed measurement remains valid JSON, but also fails shell conditionals.
[ "$STATUS" = up ]
