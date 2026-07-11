FROM zeek/zeek@sha256:f3d539d68e2a68897b02bfa302df9c7f8bcb89f338399625686fca9cc30c85f3

COPY entrypoint.sh /usr/local/bin/iaea-zeek-entrypoint

RUN chmod +x /usr/local/bin/iaea-zeek-entrypoint

ENTRYPOINT ["/usr/local/bin/iaea-zeek-entrypoint"]
