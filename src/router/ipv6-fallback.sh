#!/bin/sh
set -eu
ROOT=$1; RUNTIME=$2
exec "$RUNTIME/opt/lib/ld.so.1" --library-path "$RUNTIME/opt/lib" "$RUNTIME/opt/bin/busybox" sh "$ROOT/ipv6-routes.sh" "$ROOT" "$RUNTIME" provider
