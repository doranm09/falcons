FROM python:3.11-slim
WORKDIR /agent
COPY host_agent/requirements.txt /agent/requirements.txt
RUN pip install --no-cache-dir -r /agent/requirements.txt
COPY host_agent /agent
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/agent
ENTRYPOINT ["python", "/agent/agent.py"]
