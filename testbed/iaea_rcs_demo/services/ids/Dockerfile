# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
   --mount=type=cache,target=/var/lib/apt,sharing=locked \
   apt-get update \
 && apt-get install -y --no-install-recommends \
   iproute2 \
   libpcap0.8 \
   argus-server \
   argus-client \
 && rm -rf /var/lib/apt/lists/*

# Keep core Python deps in a separate cached layer.
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
   pip install --no-cache-dir pyod nfstream joblib numpy tqdm matplotlib

# Torch is heavy; isolate it so edits to other deps don't invalidate this layer.
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
   pip install --no-cache-dir torch

WORKDIR /app

COPY ids.py /app/ids.py
COPY ids_common.py /app/ids_common.py
COPY ids_forwarder.py /app/ids_forwarder.py
COPY inspect_flows.py /app/inspect_flows.py
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh", "/bin/sh", "-c", "while true; do sleep 3600; done"]
