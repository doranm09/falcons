FROM python:3.12-slim

# Install argus/ra for flow capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    argus-client \
    argus-server \
    iproute2 \
    docker.io \
    nmap \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir numpy

WORKDIR /app

# Default command - will be overridden by docker compose
CMD ["python", "/app/scripts/ids_network_collect_dataset.py", "--help"]
