# IAM Login Service Dockerfiles and scripts

- build-prod-image.sh: builds a production image for the login service
- push-prod-image.sh: pushes the image to dockerhub 

## Bulding the IAM login service docker image

To build the IAM login service docker image, you can use the
build-prod-image.sh script.

The script behaviour is configured via the following environment variables:

- `IAM_LOGIN_SERVICE_WAR`: this env variable points to the iam-login-service
  war file as produced by the maven build. When not set, the script will look
  for the war in the well-known location.

- `IAM_LOGIN_SERVICE_IMAGE`: sets the docker image name used by the docker
  build command. Default: indigoiam/iam-login-service

## Pushing the IAM login service image to dockerhub

To push the image built with the build-prod-image.sh script, use the
push-prod-image.sh script. 

The script behaviour is configured via the following variables:

- `IAM_LOGIN_SERVICE_IMAGE`: (mandatory) sets the docker image name used by the docker
  push command. 
- `DOCKER_REGISTRY_HOST`: if this variable is set, the image is pushed to the
  docker registry pointed by the variable instead of pushing to dockerhub.

## Optional Prometheus JMX exporter

The production image includes `jmx_prometheus_javaagent` **version 1.7.0** at
`/opt/jmx-exporter/jmx_prometheus_javaagent.jar`, and a minimal JVM-only
configuration at `/opt/jmx-exporter/config.yaml`. The JAR is downloaded from the
upstream release and verified against a pinned SHA-256 digest during the image
build. Its version and checksum are set in the Dockerfile.

The agent is **disabled by default**. Merely having the JAR on disk has no JVM
CPU, memory or startup overhead and does not open any port. To enable it,
append this option to any existing `IAM_JAVA_OPTS`:

```text
-Djmx.prometheus.exporter.logging.backend=native -javaagent:/opt/jmx-exporter/jmx_prometheus_javaagent.jar=0.0.0.0:9404:/opt/jmx-exporter/config.yaml
```

For example, in Docker Compose (do not publish port 9404 to the host):

```yaml
services:
  iam:
    environment:
      IAM_JAVA_OPTS: >-
        -Djmx.prometheus.exporter.logging.backend=native
        -javaagent:/opt/jmx-exporter/jmx_prometheus_javaagent.jar=0.0.0.0:9404:/opt/jmx-exporter/config.yaml
```

A Prometheus instance on the same trusted container network can scrape
`iam:9404/metrics`. In Kubernetes, configure the pod's environment similarly,
then use a `Service`/`ServiceMonitor` or `PodMonitor` and a restrictive
`NetworkPolicy` so only monitoring workloads can reach TCP port 9404.
The exporter HTTP listener is **not authenticated or encrypted** by the default
configuration. Never publish it publicly or proxy it through IAM's public
NGINX endpoint. Restrict ingress at network level or supply an appropriate
custom exporter configuration with authentication/TLS. The host `0.0.0.0`
allows scrapes from other containers/pods; for same-network-namespace
scrapers only, bind to `127.0.0.1` instead.

The bundled YAML limits collection to `java.lang` and `java.nio` JVM MBeans.
To expose more metrics, mount a vetted YAML configuration (read-only) over
`/opt/jmx-exporter/config.yaml` or point `-javaagent` at your own file.
Note that invalid agent arguments or YAML can prevent IAM from starting.
The agent is independent of Spring Boot Actuator and is not enabled or
managed by IAM application properties.

Upstream documentation: https://prometheus.github.io/jmx_exporter/deployment/java-agent/
