FROM debian:bookworm-slim

ARG OPENPLC_REF=b5d41356dab4aeadca0dd7ca64ba542f870b595d
ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_BREAK_SYSTEM_PACKAGES=1

WORKDIR /workdir

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gcc iproute2 python3 python3-dev python3-pip python3-venv tar \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/thiagoralves/OpenPLC_v3/archive/${OPENPLC_REF}.tar.gz" -o /tmp/openplc.tar.gz \
 && tar -xzf /tmp/openplc.tar.gz --strip-components=1 -C /workdir \
 && rm -f /tmp/openplc.tar.gz

RUN mkdir /docker_persistent

RUN ./install.sh docker \
 && touch /docker_persistent/mbconfig.cfg \
 && touch /docker_persistent/persistent.file \
 && mkdir /docker_persistent/st_files \
 && cp /workdir/webserver/openplc.db /docker_persistent/openplc.db \
 && mv /workdir/webserver/openplc.db /workdir/webserver/openplc_default.db \
 && cp /workdir/webserver/dnp3.cfg /docker_persistent/dnp3.cfg \
 && mv /workdir/webserver/dnp3.cfg /workdir/webserver/dnp3_default.cfg \
 && cp -r /workdir/webserver/st_files/ /docker_persistent/st_files/ \
 && mv /workdir/webserver/st_files /workdir/webserver/st_files_default \
 && cp /workdir/webserver/active_program /docker_persistent/active_program \
 && mv /workdir/webserver/active_program /workdir/webserver/active_program_default \
 && ln -s /docker_persistent/mbconfig.cfg /workdir/webserver/mbconfig.cfg \
 && ln -s /docker_persistent/persistent.file /workdir/webserver/persistent.file \
 && ln -s /docker_persistent/openplc.db /workdir/webserver/openplc.db \
 && ln -s /docker_persistent/dnp3.cfg /workdir/webserver/dnp3.cfg \
 && ln -s /docker_persistent/st_files /workdir/webserver/st_files \
 && ln -s /docker_persistent/active_program /workdir/webserver/active_program

COPY host_agent/requirements.txt /opt/host_agent/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /opt/host_agent/requirements.txt

COPY host_agent /opt/host_agent
COPY testbed/iaea_rcs_demo/services/openplc-v3/entrypoint.sh /usr/local/bin/openplc-lab-entrypoint
COPY testbed/iaea_rcs_demo/services/openplc-v3/compat_listener.py /opt/openplc-lab/compat_listener.py
COPY testbed/iaea_rcs_demo/services/openplc-v3/opc_bridge.py /opt/openplc-lab/opc_bridge.py
COPY testbed/iaea_rcs_demo/services/openplc-v3/seed_lab_profile.py /opt/openplc-lab/seed_lab_profile.py
COPY testbed/iaea_rcs_demo/services/openplc-v3/programs/ /opt/openplc-lab/programs/
COPY testbed/iaea_rcs_demo/services/openplc-v3/profiles/ /opt/openplc-lab/profiles/
COPY testbed/iaea_rcs_demo/services/start_host_agent.sh /usr/local/bin/start_host_agent.sh

RUN python3 -m venv /opt/openplc-lab/venv \
 && /opt/openplc-lab/venv/bin/pip install --no-cache-dir opcua

RUN chmod +x /usr/local/bin/openplc-lab-entrypoint /usr/local/bin/start_host_agent.sh

VOLUME /docker_persistent
EXPOSE 502 8080 44818 4840

ENTRYPOINT ["/usr/local/bin/openplc-lab-entrypoint"]
