#!/usr/bin/env sh
# SPDX-License-Identifier: MIT
# php2shell remote-check lab — bring up the target containers, then run the demo.
#
#   ./demo/lab.sh up        start: vulnerable 8.4.26 (:8084), fixed 8.4.27 (:8080)
#   ./demo/lab.sh down      remove the demo containers
#   ./demo/lab.sh run ...   run demo.py (extra args passed through)
#
# Requires Docker. Binds to 127.0.0.1 only. This is unpatched PHP by design:
# keep it on an isolated host.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WWW="$HERE/lab/wwwroot"
CONF="$HERE/lab/conf"

VULN_IMG="php:8.4.26-apache"
FIXED_IMG="php:8.4-apache"      # currently resolves to PHP 8.4.27

up() {
  down >/dev/null 2>&1 || true
  echo "starting php2shell remote-check lab:"
  docker run -d --name php8426 -p 127.0.0.1:8084:80 \
    -v "$WWW:/var/www/html:ro" -v "$CONF/oom.ini:/usr/local/etc/php/conf.d/zz.ini:ro" \
    "$VULN_IMG" >/dev/null
  echo "  php8426        (8.4.26 vulnerable)  http://127.0.0.1:8084"
  docker run -d --name php2shell-test -p 127.0.0.1:8080:80 \
    -v "$WWW:/var/www/html:ro" -v "$CONF/oom.ini:/usr/local/etc/php/conf.d/zz.ini:ro" \
    "$FIXED_IMG" >/dev/null
  echo "  php2shell-test (8.4.27 fixed)       http://127.0.0.1:8080"
  echo "  (both nodes use the same low-memory config so the only difference is the patch)"
  sleep 2
}

down() {
  docker rm -f php8426 php2shell-test >/dev/null 2>&1 || true
}

case "${1:-}" in
  up)   up ;;
  down) down; echo "lab removed" ;;
  run)  shift; exec python3 "$ROOT/demo.py" "$@" ;;
  *)    echo "usage: $0 {up|down|run [demo.py args]}" >&2; exit 2 ;;
esac
