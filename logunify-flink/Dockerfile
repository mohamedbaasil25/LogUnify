# syntax=docker/dockerfile:1.7
# LogUnify noise-reduction / dedup / zstd job (PyFlink 1.20.1, local mini-cluster mode). Needs Python 3.11 (PyFlink limit) and Java 11.
ARG FLINK_IMAGE=flink:1.20.1-java11
FROM ${FLINK_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip python3-venv python-is-python3 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.lock /tmp/requirements.lock
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1
# jars are provided at build time (Maven Central, see logunify-flink/README.md); they are not committed to the repository
COPY jars/*.jar /opt/flink/lib/
WORKDIR /app
COPY logunify_flink ./logunify_flink
USER flink
CMD ["python", "-m", "logunify_flink.job", "--bootstrap", "kafka:9092", "--in-topic", "logunify.raw", "--out-topic", "logunify.siem"]
