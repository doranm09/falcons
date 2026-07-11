ARG IGNITION_VERSION=8.1.39
FROM inductiveautomation/ignition:${IGNITION_VERSION}

USER root

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc iproute2 python3-dev python3-pip python3-venv \
 && rm -rf /var/lib/apt/lists/*

COPY host_agent/requirements.txt /opt/host_agent/requirements.txt
RUN python3 -m venv /opt/host_agent-venv \
 && /opt/host_agent-venv/bin/pip install --no-cache-dir -r /opt/host_agent/requirements.txt

ENV HOST_AGENT_PYTHON=/opt/host_agent-venv/bin/python

COPY host_agent /opt/host_agent
COPY testbed/iaea_rcs_demo/services/ignition/entrypoint.sh /usr/local/bin/iaea-ignition-entrypoint
COPY testbed/iaea_rcs_demo/services/start_host_agent.sh /usr/local/bin/start_host_agent.sh

RUN chmod +x /usr/local/bin/iaea-ignition-entrypoint /usr/local/bin/start_host_agent.sh

ENTRYPOINT ["/usr/local/bin/iaea-ignition-entrypoint"]
