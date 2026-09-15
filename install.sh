#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ $EUID -ne 0 ]]; then
  printf 'Запустите: sudo bash install.sh\n' >&2
  exit 1
fi
if ! command -v python3 >/dev/null; then
  command -v apt-get >/dev/null || { printf 'Поддерживаются Ubuntu/Debian с apt.\n'; exit 1; }
  apt-get update
  apt-get install -y python3
fi
exec python3 dnsctl.py install
