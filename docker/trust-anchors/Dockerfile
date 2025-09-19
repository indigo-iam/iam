FROM almalinux:9

COPY ./x509 /
COPY ./helper-scripts /

ENV PATH=/helper-scripts/x509-scripts/scripts:$PATH

RUN dnf install -y epel-release && \
      dnf -y update && \
      dnf -y install voms-clients-cpp faketime

RUN sh setup-trust.sh
