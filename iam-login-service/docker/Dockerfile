FROM eclipse-temurin:17

RUN mkdir /indigo-iam
WORKDIR /indigo-iam
CMD java ${IAM_JAVA_OPTS} -jar ${IAM_JAR}

# Embed TINI since compose v3 syntax do not support the init 
# option to run docker --init
#
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ENTRYPOINT ["/tini", "--"]
