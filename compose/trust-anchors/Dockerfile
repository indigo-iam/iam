FROM almalinux:9

COPY ./x509 /
COPY ./helper-scripts /helper-scripts
COPY ./setup-trust.sh /setup-trust.sh

ENV PATH=/helper-scripts/x509-scripts/scripts:$PATH

RUN dnf install -y epel-release && \
      dnf -y update && \
      dnf -y install voms-clients-cpp faketime

RUN sh setup-trust.sh
