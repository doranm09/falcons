# Dockerfile
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /code

# Build-time sanity check: shows Python version and how type annotations behave.
# This is useful when debugging issues like `Optional[...]` NameError at import time.
RUN python - <<'PY'\nimport sys\nprint('PYTHON_VERSION:', sys.version)\n\n# Without postponed evaluation, missing names in annotations fail at function definition time.\ntry:\n    exec(\"def f(x: Optional[int]):\\n    return x\\n\")\n    print('ANNOTATIONS: unexpected success without Optional in scope')\nexcept NameError as e:\n    print('ANNOTATIONS: NameError as expected:', e)\n\n# With postponed evaluation, annotations are stored as strings and missing names don't error immediately.\nsrc = (\n    \"from __future__ import annotations\\n\"\n    \"def g(x: Optional[int]):\\n    return x\\n\"\n    \"print('POSTPONED_ANNOTATIONS:', g.__annotations__)\\n\"\n)\nexec(src)\nPY

# Install system dependencies (keep minimal for app/celery)
RUN apt-get update && apt-get install -y \
    curl \
    iputils-ping \
    netcat-openbsd \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt /code/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy rest of the code
COPY . /code/

# Non-root runtime user
RUN useradd -m appuser && chown -R appuser:appuser /code
USER appuser
