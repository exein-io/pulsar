ARG BASE_IMAGE

FROM ${BASE_IMAGE}

ARG ARCH

RUN apt update && apt upgrade -y && apt install -y ca-certificates

COPY ./target/${ARCH}/release/pulsar-exec /usr/sbin/pulsar-exec

COPY .github/docker/pulsar.ini /var/lib/pulsar/pulsar.ini

COPY ./rules/basic-rules.yaml /var/lib/pulsar/rules/basic-rules.yaml

ENTRYPOINT [ "pulsar-exec" ]

CMD [ "pulsard" ] 
