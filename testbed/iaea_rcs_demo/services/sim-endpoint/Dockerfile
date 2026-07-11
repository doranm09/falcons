FROM python:3.12-alpine
RUN apk add --no-cache iproute2
WORKDIR /app
COPY app.py /app/app.py
COPY modbus_tcp.py /app/modbus_tcp.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "/app/app.py"]
