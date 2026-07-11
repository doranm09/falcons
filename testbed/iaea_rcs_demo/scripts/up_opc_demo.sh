#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

docker compose -f docker-compose-hybrid.yml up -d --build --remove-orphans
python3 scripts/demo_iface_names.py --apply-via-docker
python3 scripts/verify_opc_demo.py
