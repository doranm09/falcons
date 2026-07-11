FROM python:3.12-slim
ENV PIP_BREAK_SYSTEM_PACKAGES=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc iproute2 python3-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN python3 -m pip install --no-cache-dir --break-system-packages opcua

COPY host_agent/requirements.txt /opt/host_agent/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /opt/host_agent/requirements.txt

COPY host_agent /opt/host_agent
COPY testbed/iaea_rcs_demo/services/hmi/app.py /app/app.py
COPY testbed/iaea_rcs_demo/services/hmi/entrypoint.sh /entrypoint.sh
COPY testbed/iaea_rcs_demo/services/start_host_agent.sh /usr/local/bin/start_host_agent.sh

RUN chmod +x /entrypoint.sh /usr/local/bin/start_host_agent.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "/app/app.py"]
