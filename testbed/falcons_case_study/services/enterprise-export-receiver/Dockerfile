FROM python:3.12-alpine

WORKDIR /app
COPY receiver.py /app/receiver.py

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/receiver.py"]
