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
