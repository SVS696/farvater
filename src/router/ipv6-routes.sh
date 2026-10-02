#!/bin/sh
# Native ISP routes survive reboot. Own only the temporary proto-186 routes.
set -eu
ROOT=$1; RUNTIME=$2; ACTION=$3
LD="$RUNTIME/opt/lib/ld.so.1"; LIB="$RUNTIME/opt/lib"; BB="$RUNTIME/opt/bin/busybox"
bb() { "$LD" --library-path "$LIB" "$BB" "$@"; }
ip() { "$LD" --library-path "$LIB" "$RUNTIME/opt/bin/ip" "$@"; }
rci() { "$LD" --library-path "$LIB" "$RUNTIME/opt/bin/curl" --noproxy '*' --fail --silent --show-error --connect-timeout 1 --max-time 2 "http://127.0.0.1:79/rci/$1"; }
. "$ROOT/ipv6-settings.sh"
JOURNAL="$ROOT/state/ipv6-owned.tsv"
# Match the full route identity. Never flush tables or replace foreign routes.
present() {
    found_routes=$(ip -6 route show table "$1" proto 186) || return 2
    printf '%s\n' "$found_routes" | bb awk -v prefix="$3" -v device="$2" '
        BEGIN{sub(/\/128$/,"",prefix)}
        $1==prefix {dev=""; metric=""; for(i=2;i<NF;i++){if($i=="dev")dev=$(i+1);if($i=="metric")metric=$(i+1)}
        if(dev==device && metric==100) found=1} END{exit !found}'
}
provider() {
    [ -e "$JOURNAL" ] || return 0
    while read -r table device prefix extra; do
        [ -z "$extra" ] || return 64
        case "$table" in ''|*[!0-9]*) return 64;; esac
        case "$device" in ''|*[!a-zA-Z0-9_.:-]*) return 64;; esac
        case "$prefix" in ''|*[!a-fA-F0-9:/]*) return 64;; esac
        rc=0; present "$table" "$device" "$prefix" || rc=$?
        [ "$rc" -le 1 ] || return "$rc"
        if [ "$rc" = 0 ]; then
            ip -6 route del "$prefix" dev "$device" table "$table" metric 100 proto 186
        fi
        rc=0; present "$table" "$device" "$prefix" || rc=$?
        [ "$rc" = 1 ] || return 1
    done < "$JOURNAL"
    : > "$JOURNAL"
    bb rm -f "$ROOT/state/ipv6-context"
}
[ "$ACTION" != provider ] || { provider; exit; }
resolve_device() {
    # NDM's logical name is user-facing. Match its address to the kernel device;
    # never ask the user to know an nwg/eth name or assume a numbered mapping.
    scalar=$(rci "show/interface/$1/address") || return 1
    address=$(printf '%s\n' "$scalar" | bb awk '/^"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"$/ {gsub(/"/, "");print}')
    [ -n "$address" ] || return 1
    ip -o -4 address show | bb awk -v address="$address" '
        {split($4,a,"/"); if(a[1]==address){name=$2;sub(/@.*/,"",name);count++}}
        END{if(count!=1)exit 1; print name}'
}
TABLE=$(rci "show/ip/policy/$POLICY/table6")
case "$TABLE" in ''|*[!0-9]*) exit 64;; esac
[ "${#TABLE}" -le 10 ] && [ "$TABLE" -ge 256 ] && [ "$TABLE" -le 2147483647 ] || exit 64
SERVER_DEVICE=$(resolve_device "$SERVER_CONNECTION")
PROVIDER_DEVICE=$(resolve_device "$PROVIDER_CONNECTION")
[ -n "$SERVER_DEVICE" ] && [ -n "$PROVIDER_DEVICE" ] && [ "$SERVER_DEVICE" != "$PROVIDER_DEVICE" ] || exit 1
for prefix in $PREFIXES; do
    ip -6 route show table "$TABLE" | bb awk -v prefix="$prefix" -v device="$PROVIDER_DEVICE" '
        BEGIN{sub(/\/128$/,"",prefix)}
        $1==prefix && !/linkdown/ {dev="";metric="";for(i=2;i<NF;i++){if($i=="dev")dev=$(i+1);if($i=="metric")metric=$(i+1)}
        if(dev==device && metric==900)found=1} END{exit !found}'
done
case "$ACTION" in
    check)
        mode=$4
        if [ "$mode" = home ]; then
            [ "$(bb cat "$ROOT/state/ipv6-context")" = "$TABLE $SERVER_DEVICE $PROVIDER_DEVICE" ] || exit 1
            for prefix in $PREFIXES; do present "$TABLE" "$SERVER_DEVICE" "$prefix" || exit 1; done
        else
            [ ! -s "$JOURNAL" ] || exit 1
        fi
        ;;
    home)
        provider
        # A conflict is an error, not authority to overwrite someone else's route.
        for prefix in $PREFIXES; do
            rc=0; present "$TABLE" "$SERVER_DEVICE" "$prefix" || rc=$?
            [ "$rc" = 1 ] || exit 73
            printf '%s\t%s\t%s\n' "$TABLE" "$SERVER_DEVICE" "$prefix" >> "$JOURNAL"
            ip -6 route add "$prefix" dev "$SERVER_DEVICE" table "$TABLE" metric 100 proto 186
            present "$TABLE" "$SERVER_DEVICE" "$prefix" || exit 1
        done
        printf '%s %s %s\n' "$TABLE" "$SERVER_DEVICE" "$PROVIDER_DEVICE" > "$ROOT/state/ipv6-context"
        ;;
    *) exit 64;;
esac
