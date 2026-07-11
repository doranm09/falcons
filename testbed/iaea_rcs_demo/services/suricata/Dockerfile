FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends suricata ca-certificates jq \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/iaea-suricata-entrypoint

RUN chmod +x /usr/local/bin/iaea-suricata-entrypoint

ENTRYPOINT ["/usr/local/bin/iaea-suricata-entrypoint"]
