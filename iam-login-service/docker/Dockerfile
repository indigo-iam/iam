FROM eclipse-temurin:17

RUN mkdir /indigo-iam
WORKDIR /indigo-iam

RUN apt update && apt install -y maven && apt clean

CMD mvn -pl iam-login-service -am spring-boot:run ${IAM_JAVA_OPTS}

