FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /opt/siem-runtime

COPY forwarder.py /opt/siem-runtime/forwarder.py

ENTRYPOINT ["python", "/opt/siem-runtime/forwarder.py"]
