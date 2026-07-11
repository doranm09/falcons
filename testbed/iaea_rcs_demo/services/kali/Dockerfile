FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_BREAK_SYSTEM_PACKAGES=1

WORKDIR /opt/kali

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        hping3 \
        nikto \
        sqlmap \
        curl \
        jq \
        netcat-traditional \
        iputils-ping \
        ca-certificates \
        iproute2 \
        python3 \
        python3-pip \
    && python3 -m pip install --no-cache-dir --break-system-packages pymodbus flask \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


COPY modbus_inject.py /opt/kali/modbus_inject.py
COPY kali_attack_api.py /opt/kali/kali_attack_api.py

RUN chmod +x /opt/kali/modbus_inject.py \
    && ln -sf /opt/kali/modbus_inject.py /usr/local/bin/modbus_inject.py \
    && ln -sf /opt/kali/modbus_inject.py /usr/local/bin/modbus_inject

ENV FLASK_APP=/opt/kali/kali_attack_api.py
CMD ["flask", "run", "--host=0.0.0.0", "--port=5001"]
