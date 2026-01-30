FROM alpine:3.19
RUN apk add --no-cache python3 iptables
WORKDIR /app
COPY conduit.py /app/conduit.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
