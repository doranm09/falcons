FROM postgres:15

USER root

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc iproute2 python3-dev python3-pip \
 && rm -rf /var/lib/apt/lists/*

COPY host_agent/requirements.txt /opt/host_agent/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /opt/host_agent/requirements.txt

COPY host_agent /opt/host_agent
COPY testbed/iaea_rcs_demo/services/postgres/entrypoint.sh /usr/local/bin/iaea-postgres-entrypoint
COPY testbed/iaea_rcs_demo/services/start_host_agent.sh /usr/local/bin/start_host_agent.sh

RUN chmod +x /usr/local/bin/iaea-postgres-entrypoint /usr/local/bin/start_host_agent.sh

ENTRYPOINT ["/usr/local/bin/iaea-postgres-entrypoint"]
CMD ["postgres"]
