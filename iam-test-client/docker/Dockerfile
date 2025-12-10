FROM eclipse-temurin:17

RUN mkdir /app
WORKDIR /app

RUN apt update && apt install -y maven && apt clean

CMD mvn -pl iam-test-client -am spring-boot:run ${IAM_CLIENT_JAVA_OPTS}
