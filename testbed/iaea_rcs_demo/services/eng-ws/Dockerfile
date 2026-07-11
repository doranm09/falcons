FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV HOST_AGENT_PYTHON=/opt/eng-ws/venv/bin/python

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      dbus-x11 \
      gcc \
      iproute2 \
      iputils-ping \
      libasound2t64 \
      libgtk-3-0 \
      libnss3 \
      libx11-xcb1 \
      libxcomposite1 \
      libxcursor1 \
      libxi6 \
      libxinerama1 \
      libxrandr2 \
      libxrender1 \
      libxtst6 \
      netcat-openbsd \
      novnc \
      openbox \
      procps \
      python3 \
      python3-venv \
      python3-dev \
      python3-xdg \
      tcpdump \
      websockify \
      x11vnc \
      xauth \
      xdg-utils \
      xterm \
      xvfb \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/eng-ws

RUN useradd -m -s /bin/bash engineer

RUN python3 -m venv /opt/eng-ws/venv \
 && /opt/eng-ws/venv/bin/pip install --no-cache-dir cryptography opcua

COPY host_agent/requirements.txt /opt/host_agent/requirements.txt
RUN /opt/eng-ws/venv/bin/pip install --no-cache-dir -r /opt/host_agent/requirements.txt

COPY host_agent /opt/host_agent
COPY testbed/iaea_rcs_demo/services/eng-ws/designerlauncher.tar.gz /opt/eng-ws/designerlauncher.tar.gz
COPY testbed/iaea_rcs_demo/services/eng-ws/entrypoint.sh /entrypoint.sh
COPY testbed/iaea_rcs_demo/services/eng-ws/desktop-session.sh /opt/eng-ws/desktop-session.sh
COPY testbed/iaea_rcs_demo/services/eng-ws/status_http.py /opt/eng-ws/status_http.py
COPY testbed/iaea_rcs_demo/services/eng-ws/opc_read.py /usr/local/bin/opc-read
COPY testbed/iaea_rcs_demo/services/start_host_agent.sh /usr/local/bin/start_host_agent.sh

RUN tar -xzf /opt/eng-ws/designerlauncher.tar.gz -C /opt/eng-ws \
 && rm /opt/eng-ws/designerlauncher.tar.gz \
 && install -d /var/lib/openbox \
 && printf '%s\n' \
      '<?xml version="1.0" encoding="UTF-8"?>' \
      '<openbox_menu xmlns="http://openbox.org/3.4/menu">' \
      '  <menu id="root-menu" label="Openbox 3">' \
      '    <item label="Terminal">' \
      '      <action name="Execute"><command>xterm</command></action>' \
      '    </item>' \
      '  </menu>' \
      '</openbox_menu>' > /var/lib/openbox/debian-menu.xml \
 && chmod +x /entrypoint.sh /usr/local/bin/opc-read /opt/eng-ws/desktop-session.sh /usr/local/bin/start_host_agent.sh \
 && chmod +x /opt/eng-ws/designerlauncher/install.sh /opt/eng-ws/designerlauncher/designerlauncher.sh \
 && chown -R engineer:engineer /home/engineer /opt/eng-ws/designerlauncher

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/opt/eng-ws/venv/bin/python", "/opt/eng-ws/status_http.py"]
