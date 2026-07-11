# Dockerfile
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /code

# Install system dependencies (keep minimal for app/celery)
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    iputils-ping \
    netcat-openbsd \
    nmap \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Install server-side SBOM vulnerability scanners used by the dashboard.
# The app task will use these when present and skip cleanly if they are missing.
RUN set -eux; \
    curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin; \
    curl -fsSL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install dependencies
COPY requirements.txt /code/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy rest of the code
COPY . /code/

# Non-root runtime user
RUN useradd -m appuser && chown -R appuser:appuser /code
USER appuser
