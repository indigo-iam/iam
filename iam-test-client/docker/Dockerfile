FROM eclipse-temurin:17

RUN mkdir /app
WORKDIR /app

CMD java ${IAM_CLIENT_JAVA_OPTS} -jar ${IAM_CLIENT_JAR}

# Embed TINI since compose v3 syntax do not support the init
# option to run docker --init
#
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ENTRYPOINT ["/tini", "--"]
