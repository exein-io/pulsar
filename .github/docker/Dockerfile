ARG BASE_IMAGE

FROM ${BASE_IMAGE}

ARG ARCH

RUN apt update && apt upgrade -y && apt install -y ca-certificates libsqlite3-0

COPY ./target/${ARCH}/release/pulsard /usr/sbin/pulsard
COPY ./target/${ARCH}/release/pulsar /usr/sbin/pulsar

COPY .github/docker/pulsar.toml /etc/pulsar/pulsar.toml

COPY ./rules/ /etc/pulsar/rules/

ENTRYPOINT [ "pulsard" ]
