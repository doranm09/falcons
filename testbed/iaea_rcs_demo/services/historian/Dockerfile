FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iputils-ping netcat-openbsd \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir opcua influxdb-client
COPY collector.py /collector.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "/collector.py"]
