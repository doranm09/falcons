#!/usr/bin/env bash
set -euo pipefail

compose_file="${1:-compose.yaml}"
max_attempts="${MAX_ATTEMPTS:-3}"

if [[ ! -f "$compose_file" ]]; then
  echo "compose file not found: $compose_file" >&2
  exit 1
fi

mapfile -t images < <(docker compose -f "$compose_file" config --images | awk 'NF' | sort -u)

if [[ "${#images[@]}" -eq 0 ]]; then
  echo "no images found in $compose_file" >&2
  exit 1
fi

for image in "${images[@]}"; do
  echo "Pulling $image"

  attempt=1
  while true; do
    if docker pull "$image"; then
      break
    fi

    if [[ "$attempt" -ge "$max_attempts" ]]; then
      echo "failed to pull $image after $attempt attempts" >&2
      exit 1
    fi

    echo "retrying $image in 5 seconds (attempt $((attempt + 1))/$max_attempts)" >&2
    sleep 5
    attempt=$((attempt + 1))
  done
done
