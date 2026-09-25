#!/usr/bin/env bash
# Builds the jar if needed, then runs the integration smoke test against a fake upstream.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX="$(cd "$HERE/.." && pwd)"
if [ ! -f "$LINUX/build/netshield-dns.jar" ]; then
    "$LINUX/packaging/build-deb.sh" >/dev/null
fi
exec python3 "$HERE/smoke.py" --jar "$LINUX/build/netshield-dns.jar" "$@"
