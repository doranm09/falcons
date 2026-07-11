# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
   pip install --no-cache-dir influxdb-client numpy pyod joblib tqdm

# CPU-only torch is sufficient for the lab IDS models and avoids multi-GB CUDA wheels.
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
   pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch

WORKDIR /app

COPY ids_process.py /app/ids_process.py
COPY ids_process_forwarder.py /app/ids_process_forwarder.py

CMD ["python", "ids_process_forwarder.py"]
