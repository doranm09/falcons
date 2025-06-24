# Dockerfile
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /code

# Install system dependencies
# Install dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
    libpcap-dev \
    build-essential \
    python3-dev \
    gcc \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries
RUN pip install --no-cache-dir \
    scapy \
    pyshark \
    python-gvm

# Ensure TShark permissions (non-root if needed)
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Install dependencies
COPY requirements.txt /code/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy rest of the code
COPY . /code/
