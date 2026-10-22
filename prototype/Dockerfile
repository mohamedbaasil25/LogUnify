FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get -y --no-install-recommends upgrade && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin logunify && mkdir /data && chown 10001:10001 /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1 LOGUNIFY_DLQ_PATH=/data/dead_letter.jsonl LOGUNIFY_OUTPUT_PATH=/data/events.jsonl
USER 10001
CMD ["python", "app.py"]
