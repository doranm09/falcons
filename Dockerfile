# Dockerfile
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /code

# Install system dependencies (keep minimal for app/celery)
RUN apt-get update && apt-get install -y \
    curl \
    iputils-ping \
    netcat-openbsd \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt /code/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy rest of the code
COPY . /code/

# Non-root runtime user
RUN useradd -m appuser && chown -R appuser:appuser /code
USER appuser
