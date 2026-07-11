FROM alpine:3.20
RUN set -eux; \
    for attempt in 1 2 3; do \
        apk add --no-cache iptables iproute2 bash curl && exit 0; \
        echo "apk add failed on attempt ${attempt}; retrying..." >&2; \
        sleep 2; \
    done; \
    exit 1
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
