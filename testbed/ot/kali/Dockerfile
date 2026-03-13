FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        nikto \
        sqlmap \
        curl \
        jq \
        netcat-traditional \
        iputils-ping \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash", "-lc", "sleep infinity"]
