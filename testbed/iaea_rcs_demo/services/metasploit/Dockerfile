FROM metasploitframework/metasploit-framework:latest

USER root

RUN apk add --no-cache \
    build-base \
    iproute2 \
    linux-headers \
    py3-pip \
    python3-dev

COPY host_agent/requirements.txt /opt/host_agent/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /opt/host_agent/requirements.txt

COPY host_agent /opt/host_agent
COPY testbed/iaea_rcs_demo/services/metasploit/entrypoint.sh /usr/local/bin/iaea-metasploit-entrypoint
COPY testbed/iaea_rcs_demo/services/start_host_agent.sh /usr/local/bin/start_host_agent.sh

RUN chmod +x /usr/local/bin/iaea-metasploit-entrypoint /usr/local/bin/start_host_agent.sh

ENTRYPOINT ["/usr/local/bin/iaea-metasploit-entrypoint"]
