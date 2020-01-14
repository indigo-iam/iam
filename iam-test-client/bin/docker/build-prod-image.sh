#!/bin/bash
set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )"

if [[ -z ${IAM_TEST_CLIENT_JAR} ]]; then
  LOCAL_BUILD_JAR=${DIR}/../target/iam-test-client.jar
  if [[ -r ${LOCAL_BUILD_JAR} ]]; then
    IAM_TEST_CLIENT_JAR=${LOCAL_BUILD_JAR}
  fi
fi

if [[ ! -r ${IAM_TEST_CLIENT_JAR} ]]; then
  echo "Please set the IAM_TEST_CLIENT_JAR env variable"
  exit 1
fi

echo "Building image using jar from ${IAM_TEST_CLIENT_JAR}"

# Default name for iam login service docker image
default_image_name="indigoiam/iam-test-client"

IAM_TEST_CLIENT_IMAGE=${IAM_TEST_CLIENT_IMAGE:-${default_image_name}}
cd ${DIR}
cp ${IAM_TEST_CLIENT_JAR} iam-test-client.jar

docker build -f Dockerfile.prod \
  --rm=true --no-cache=true \
  -t ${IAM_TEST_CLIENT_IMAGE} .

if [[ -z ${IAM_LOGIN_SERVICE_VERSION} ]]; then
  pushd ../../
  POM_VERSION="v$(sh utils/print-pom-version.sh)"
  popd
else
  POM_VERSION="${IAM_LOGIN_SERVICE_VERSION}"
fi

GIT_COMMIT_SHA=$(git rev-parse --short HEAD)
GIT_BRANCH_NAME=$(echo ${BRANCH_NAME-$(git rev-parse --abbrev-ref HEAD)}|sed 's#/#_#g')

docker tag ${IAM_TEST_CLIENT_IMAGE} ${IAM_TEST_CLIENT_IMAGE}:${POM_VERSION}-${GIT_COMMIT_SHA}
docker tag ${IAM_TEST_CLIENT_IMAGE} ${IAM_TEST_CLIENT_IMAGE}:${POM_VERSION}-latest

if [[ -n ${GIT_BRANCH_NAME} ]] && [[ "${GIT_BRANCH_NAME}" != "HEAD" ]]; then
  docker tag ${IAM_TEST_CLIENT_IMAGE} ${IAM_TEST_CLIENT_IMAGE}:${GIT_BRANCH_NAME}-latest
fi

rm iam-test-client.jar
