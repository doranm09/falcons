FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV PIP_BREAK_SYSTEM_PACKAGES=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc iproute2 iputils-ping netcat-openbsd python3-dev \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m pip install --no-cache-dir --break-system-packages opcua influxdb-client

COPY host_agent/requirements.txt /opt/host_agent/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /opt/host_agent/requirements.txt

COPY host_agent /opt/host_agent
COPY testbed/iaea_rcs_demo/services/historian/collector.py /collector.py
COPY testbed/iaea_rcs_demo/services/historian/entrypoint.sh /entrypoint.sh
COPY testbed/iaea_rcs_demo/services/start_host_agent.sh /usr/local/bin/start_host_agent.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/start_host_agent.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "/collector.py"]
