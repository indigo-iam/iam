#!/bin/bash
set -ex

default_image_name="indigoiam/iam-test-client"
IAM_TEST_CLIENT_IMAGE=${IAM_TEST_CLIENT_IMAGE:-${default_image_name}}

if [[ -z ${IAM_LOGIN_SERVICE_VERSION} ]]; then
  pushd ../../
  POM_VERSION="v$(sh utils/print-pom-version.sh)"
  popd
else
  POM_VERSION="${IAM_LOGIN_SERVICE_VERSION}"
fi

GIT_COMMIT_SHA=$(git rev-parse --short HEAD)

GIT_BRANCH_NAME=$(echo ${BRANCH_NAME-$(git rev-parse --abbrev-ref HEAD)}|sed 's#/#_#g')

POM_VERSION_TAG=${IAM_TEST_CLIENT_IMAGE}:${POM_VERSION}-${GIT_COMMIT_SHA}
POM_VERSION_LATEST_TAG=${IAM_TEST_CLIENT_IMAGE}:${POM_VERSION}-latest
BRANCH_LATEST_TAG=${IAM_TEST_CLIENT_IMAGE}:${GIT_BRANCH_NAME}-latest

if [[ -n ${DOCKER_REGISTRY_HOST} ]]; then
  docker tag ${POM_VERSION_TAG} ${DOCKER_REGISTRY_HOST}/${POM_VERSION_TAG}
  docker tag ${POM_VERSION_LATEST_TAG} ${DOCKER_REGISTRY_HOST}/${POM_VERSION_LATEST_TAG}

  docker push ${DOCKER_REGISTRY_HOST}/${POM_VERSION_TAG}
  docker push ${DOCKER_REGISTRY_HOST}/${POM_VERSION_LATEST_TAG}

  if [ "${GIT_BRANCH_NAME}" != "HEAD" ]; then
    docker tag ${BRANCH_LATEST_TAG} ${DOCKER_REGISTRY_HOST}/${BRANCH_LATEST_TAG}
    docker push ${DOCKER_REGISTRY_HOST}/${BRANCH_LATEST_TAG}
  fi
else
  docker push ${POM_VERSION_TAG}
  docker push ${POM_VERSION_LATEST_TAG}
  if [ "${GIT_BRANCH_NAME}" != "HEAD" ]; then
    docker push ${BRANCH_LATEST_TAG}
  fi
fi
