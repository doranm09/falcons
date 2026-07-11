FROM python:3.11-slim
WORKDIR /agent
ENV PIP_BREAK_SYSTEM_PACKAGES=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*
COPY host_agent/requirements.txt /agent/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /agent/requirements.txt
COPY host_agent /agent
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/agent
ENTRYPOINT ["python", "/agent/agent.py"]
