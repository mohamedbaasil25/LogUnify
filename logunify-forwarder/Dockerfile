# syntax=docker/dockerfile:1.7
# Vector forwarder (Kafka logunify.ecs -> Elasticsearch / Splunk HEC / Wazuh file). Pin by digest for production.
ARG VECTOR_IMAGE=timberio/vector:0.58.0-debian
FROM ${VECTOR_IMAGE}
COPY vector/vector.d /etc/vector/vector.d
# secrets are mounted as files (SECRET[fwd.<name>] backend), never baked in or passed as env vars
ENV VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true SECRETS_DIR=/run/secrets
ENTRYPOINT ["/usr/bin/vector"]
CMD ["--config-dir", "/etc/vector/vector.d"]
