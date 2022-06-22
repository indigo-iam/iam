#!/bin/bash
set -e

if [[ $# -ne 1 ]]; then
  echo "This script requires a tag parameter"
  echo "Usage: push-images.sh v1.8.0.20211127"
  exit 1
fi

if [[ -n ${DEBUG} ]]; then
  set -x
fi

IMAGES="indigoiam/iam-login-service-bp indigoiam/iam-test-client-bp indigoiam/voms-aa-bp"

# The current script directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )"
POM_VERSION=$(${DIR}/print-pom-version.sh)

TAG=$1

GIT_HEAD_SHA=$(git rev-parse --short HEAD)
GIT_COMMIT_SHA=${GIT_HEAD_SHA:0:7}

for img in ${IMAGES}; do 
  echo "Tagging ${img}:${POM_VERSION}-${GIT_COMMIT_SHA} -> ${img}:${TAG}"
  docker tag ${img}:${POM_VERSION}-${GIT_COMMIT_SHA} ${img}:${TAG}
  docker push ${img}:${TAG}
  docker push ${img}:${POM_VERSION}-${GIT_COMMIT_SHA}
done
