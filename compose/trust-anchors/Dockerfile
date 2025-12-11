FROM almalinux:9

COPY ./x509 /
COPY ./setup-trust.sh /setup-trust.sh

RUN dnf install -y epel-release && \
      dnf -y update && \
      dnf -y install voms-clients-cpp faketime git && \
      git clone https://baltig.infn.it/mw-devel/helper-scripts.git

ENV PATH=/helper-scripts/x509-scripts/scripts:$PATH

RUN sh setup-trust.sh
