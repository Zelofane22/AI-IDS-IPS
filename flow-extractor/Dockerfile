FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data/flows

# NFStream writes a temporary CSV into the current directory; /tmp is writable
# even when the container root filesystem is read-only.
WORKDIR /tmp

ENTRYPOINT ["python", "/app/app/extract.py"]
