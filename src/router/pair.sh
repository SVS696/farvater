#!/bin/sh
# Owned IPv4 pair for a provisioned pilot. settings.sh is generated and root-owned.
# Native ISP policy/DNS must already be saved and independently verified.
set -eu
[ "$#" = 3 ] || exit 64
ROOT=$1; RUNTIME=$2; ACTION=$3
case "$ROOT:$RUNTIME" in *[!a-zA-Z0-9_./:-]*|*..*) exit 64;; esac
case "$ROOT:$RUNTIME" in /tmp/okopy-*:/tmp/okopy-*) ;; *) exit 64;; esac
. "$ROOT/pair-settings.sh"
LD="$RUNTIME/opt/lib/ld.so.1"; LIB="$RUNTIME/opt/lib"; BB="$RUNTIME/opt/bin/busybox"
export XTABLES_LIBDIR="$LIB/iptables"
bb() { "$LD" --library-path "$LIB" "$BB" "$@"; }
ipt() { "$LD" --library-path "$LIB" "$RUNTIME/opt/sbin/iptables" "$@"; }
ip() { "$LD" --library-path "$LIB" "$RUNTIME/opt/sbin/ip" "$@"; }
ct() { "$LD" --library-path "$LIB" "$RUNTIME/opt/sbin/conntrack" "$@"; }
CHAIN=OKOPY_CTL_MODE; MARK=0xffffaad
clear_dns() {
    for proto in udp tcp; do
        rc=0
        ct -D -p "$proto" --orig-src "$CLIENT" --orig-dst "$ROUTER" --dport 53 > "$ROOT/state/conntrack-$proto.log" 2>&1 || rc=$?
        [ "$rc" -le 1 ] || return 1
    done
}
rule() {
    table=$1; position=$2; shift 2
    case "$operation" in
    add)
        if ipt -t "$table" -C "$@" 2>/dev/null; then return 0; else rc=$?; [ "$rc" = 1 ] || return 1; fi
        ipt -t "$table" "$position" "$@";;
    check) ipt -t "$table" -C "$@";;
    remove)
        count=0
        while :; do
            rc=0; ipt -t "$table" -C "$@" 2>/dev/null || rc=$?
            case "$rc" in 1) break;; 0) ;; *) return 1;; esac
            ipt -t "$table" -D "$@" || return 1
            count=$((count+1)); [ "$count" -lt 8 ] || return 1
        done;;
    esac
}
nat_rules() {
    for proto in udp tcp; do
        rule nat -I PREROUTING -i br0 -s "$CLIENT/32" -d "$ROUTER/32" -p "$proto" --dport 53 -m mark --mark "$MARK" -j DNAT --to-destination "$SERVER:15454" || return 1
        rule nat -I POSTROUTING -o br0 -s "$CLIENT/32" -d "$SERVER/32" -p "$proto" --dport 15454 -m mark --mark "$MARK" -j ACCEPT || return 1
    done
    for target in $TARGETS; do
        rule nat -I POSTROUTING -o br0 -s "$CLIENT/32" -d "$target" -p tcp --dport 443 -m mark --mark "$MARK" -j ACCEPT || return 1
    done
}
hooks() {
    # NDM may already have deleted this entire table's owned chain. A jump to
    # an absent chain cannot exist; iptables -C otherwise returns syntax code 2.
    if [ "$operation" = remove ] && ! ipt -t mangle -S "$CHAIN" >/dev/null 2>&1; then return 0; fi
    for proto in udp tcp; do
        rule mangle -A PREROUTING -i br0 -s "$CLIENT/32" -d "$ROUTER/32" -p "$proto" --dport 53 -m mac --mac-source "$CLIENT_MAC" -j "$CHAIN" || return 1
    done
    for target in $TARGETS; do
        rule mangle -A PREROUTING -i br0 -s "$CLIENT/32" -d "$target" -p tcp --dport 443 -m mac --mac-source "$CLIENT_MAC" -j "$CHAIN" || return 1
    done
}
integrity() {
    operation=check; nat_rules || return 1; hooks || return 1
    ip rule show | bb grep -Eq '^90:.*fwmark 0xffffaad lookup 150[[:space:]]*$' || return 1
    ip route show table 150 | bb awk -v server="$SERVER" 'NF==5 && $1=="default" && $2=="via" && $3==server && $4=="dev" && $5=="br0" {good++} END {exit !(NR==1 && good==1)}' || return 1
    # Mark selection must stay after native policy marking; DNS/SNAT exceptions
    # must stay before native NAT. Presence alone cannot prove this ordering.
    ipt -t mangle -S PREROUTING | bb awk '/^-A / {if(index($0,"-j OKOPY_CTL_MODE")) own=1; else if(own) bad=1} END {exit bad}' || return 1
    for chain in PREROUTING POSTROUTING; do
        ipt -t nat -S "$chain" | bb awk '/^-A / {if(index($0,"--mark 0xffffaad")) {if(other) bad=1} else other=1} END {exit bad}' || return 1
    done
    lines=$(ipt -t mangle -S "$CHAIN" | bb wc -l)
    [ "$lines" = 2 ] || return 1
    ipt -t mangle -C "$CHAIN" -j RETURN 2>/dev/null || ipt -t mangle -C "$CHAIN" -j MARK --set-mark "$MARK"
}
case "$ACTION" in
install)
    [ ! -e "$ROOT/state/pair-owned" ]
    if ipt -t mangle -S "$CHAIN" >/dev/null 2>&1; then exit 73; fi
    [ -z "$(ip route show table 150)" ]
    if ip rule show | bb grep -q '^90:'; then exit 73; fi
    # Ownership before the first mutation allows exact cleanup of partial setup.
    : > "$ROOT/state/pair-owned"
    ipt -t mangle -N "$CHAIN"
    ipt -t mangle -A "$CHAIN" -j RETURN
    ip route add table 150 default via "$SERVER" dev br0
    ip rule add pref 90 fwmark "$MARK" table 150
    operation=add; nat_rules; hooks
    integrity
    printf 'provider\n' > "$ROOT/state/pair-mode";;
repair)
    [ -e "$ROOT/state/pair-owned" ]
    # NDM rebuilds tables independently. Detach selection first, rebuild only
    # our rules, and retain an already-correct route to avoid another NDM event.
    operation=remove; hooks; nat_rules
    if ipt -t mangle -S "$CHAIN" >/dev/null 2>&1; then ipt -t mangle -F "$CHAIN"; else ipt -t mangle -N "$CHAIN"; fi
    ipt -t mangle -A "$CHAIN" -j RETURN
    if [ -z "$(ip route show table 150)" ]; then ip route add table 150 default via "$SERVER" dev br0; fi
    if ! ip rule show | bb grep -q '^90:'; then ip rule add pref 90 fwmark "$MARK" table 150; fi
    clear_dns
    operation=add; nat_rules; hooks
    integrity
    printf 'provider\n' > "$ROOT/state/pair-mode";;
check) integrity;;
home)
    [ -e "$ROOT/state/pair-owned" ]; integrity
    ipt -t mangle -R "$CHAIN" 1 -j MARK --set-mark "$MARK"
    clear_dns
    printf 'home\n' > "$ROOT/state/pair-mode";;
provider)
    [ -e "$ROOT/state/pair-owned" ]
    if ipt -t mangle -S "$CHAIN" >/dev/null 2>&1; then ipt -t mangle -R "$CHAIN" 1 -j RETURN; fi
    clear_dns
    printf 'provider\n' > "$ROOT/state/pair-mode";;
remove)
    [ -e "$ROOT/state/pair-owned" ] || exit 0
    # Detach every selector before removing the route or DNS translation.
    operation=remove; hooks; nat_rules
    if ipt -t mangle -S "$CHAIN" >/dev/null 2>&1; then
        ipt -t mangle -F "$CHAIN"; ipt -t mangle -X "$CHAIN"
    fi
    ip rule del pref 90 fwmark "$MARK" table 150 2>/dev/null || true
    ip route del table 150 default via "$SERVER" dev br0 2>/dev/null || true
    clear_dns
    if ipt -t mangle -S "$CHAIN" >/dev/null 2>&1; then exit 73; fi
    [ -z "$(ip route show table 150)" ]
    if ip rule show | bb grep -q '^90:'; then exit 73; fi
    bb rm -f "$ROOT/state/pair-owned"
    printf 'provider\n' > "$ROOT/state/pair-mode";;
*) exit 64;;
esac
