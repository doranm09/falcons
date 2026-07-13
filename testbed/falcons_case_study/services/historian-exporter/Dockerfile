FROM python:3.12-alpine

WORKDIR /app
COPY exporter.py /app/exporter.py

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/exporter.py"]
