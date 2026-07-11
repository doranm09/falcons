ARG IGNITION_VERSION=8.1.39
FROM inductiveautomation/ignition:${IGNITION_VERSION}

USER root

RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/iaea-ignition-entrypoint

RUN chmod +x /usr/local/bin/iaea-ignition-entrypoint

ENTRYPOINT ["/usr/local/bin/iaea-ignition-entrypoint"]
