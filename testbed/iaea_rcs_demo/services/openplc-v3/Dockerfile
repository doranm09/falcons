FROM debian:bookworm-slim

ARG OPENPLC_REF=b5d41356dab4aeadca0dd7ca64ba542f870b595d
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /workdir

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl iproute2 python3 python3-venv tar \
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

COPY entrypoint.sh /usr/local/bin/openplc-lab-entrypoint
COPY compat_listener.py /opt/openplc-lab/compat_listener.py
COPY opc_bridge.py /opt/openplc-lab/opc_bridge.py
COPY seed_lab_profile.py /opt/openplc-lab/seed_lab_profile.py
COPY programs/ /opt/openplc-lab/programs/
COPY profiles/ /opt/openplc-lab/profiles/

RUN python3 -m venv /opt/openplc-lab/venv \
 && /opt/openplc-lab/venv/bin/pip install --no-cache-dir opcua

RUN chmod +x /usr/local/bin/openplc-lab-entrypoint

VOLUME /docker_persistent
EXPOSE 502 8080 44818 4840

ENTRYPOINT ["/usr/local/bin/openplc-lab-entrypoint"]
