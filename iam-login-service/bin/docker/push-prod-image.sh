#!/bin/bash
#
# Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -ex

# The current script directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )"
cd ${DIR}

default_image_name="indigoiam/iam-login-service"

IAM_LOGIN_SERVICE_IMAGE=${IAM_LOGIN_SERVICE_IMAGE:-${default_image_name}}

if [[ -z ${IAM_LOGIN_SERVICE_VERSION} ]]; then
  pushd ../../
  POM_VERSION="v$(sh utils/print-pom-version.sh)"
  popd
else
  POM_VERSION="${IAM_LOGIN_SERVICE_VERSION}"
fi

GIT_COMMIT_SHA=$(git rev-parse --short HEAD)

GIT_BRANCH_NAME=$(echo ${BRANCH_NAME-$(git rev-parse --abbrev-ref HEAD)}|sed 's#/#_#g')

POM_VERSION_TAG=${IAM_LOGIN_SERVICE_IMAGE}:${POM_VERSION}-${GIT_COMMIT_SHA}
POM_VERSION_LATEST_TAG=${IAM_LOGIN_SERVICE_IMAGE}:${POM_VERSION}-latest
BRANCH_LATEST_TAG=${IAM_LOGIN_SERVICE_IMAGE}:${GIT_BRANCH_NAME}-latest

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
