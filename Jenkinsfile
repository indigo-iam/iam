#!/usr/bin/env groovy

def maybeArchiveJUnitReports(){
  def hasJunitReports = fileExists 'iam-login-service/target/surefire-reports'
  if (hasJunitReports) {
    junit '**/target/surefire-reports/TEST-*.xml'
  }
}

def maybeArchiveJUnitReportsWithJacoco(){
  def hasJunitReports = fileExists 'iam-login-service/target/surefire-reports'
  if (hasJunitReports) {
    junit '**/target/surefire-reports/TEST-*.xml'
    step( [ $class: 'JacocoPublisher' ] )
  }
}


pipeline {

  agent { label 'java17' }

  options {
    ansiColor('xterm')
    buildDiscarder(logRotator(numToKeepStr: '5'))
    skipDefaultCheckout()
    timeout(time: 1, unit: 'HOURS')
    timestamps()
  }

  parameters {
    booleanParam(name: 'SKIP_TESTS', defaultValue: false, description: 'Skip tests')
    booleanParam(name: 'RUN_SONAR', defaultValue: false, description: 'Runs SONAR analysis')
    booleanParam(name: 'BUILD_DOCKER_IMAGES', defaultValue: false, description: 'Build docker images')
    booleanParam(name: 'PUSH_TO_DOCKERHUB', defaultValue: false, description: 'Push to Dockerhub')
  }

  triggers { cron('@daily') }

  environment {
    DOCKER_REGISTRY_HOST = "${env.DOCKER_REGISTRY_HOST}"
    SONAR_USER_HOME = "${env.WORKSPACE}/.sonar"
    SONAR_ORGANIZATION = "indigo-iam"
    SONAR_HOST_URL = "https://sonarcloud.io"
    SONAR_PROJECT_KEY = "indigo-iam_iam"
    SONAR_TOKEN = credentials('sonar_token_vianello')
  }

  stages {

    stage('build, test, package'){
      stages {

        stage('checkout') {
          steps {
              deleteDir()
              checkout scm
              stash name: 'code', useDefaultExcludes: false
          }
        }

        stage('license-check') {
          steps {
              sh 'mvn -B license:check'
          }
        }

        stage('compile') {
          steps {
            sh 'mvn -B compile'
          }
        }

        stage('Tests (no Sonar analysis)') {
          when{
            allOf{
              not {
                expression { return params.RUN_SONAR }
              }
              not {
                expression { return params.SKIP_TESTS }
              }
            }
          }

          steps {
            sh 'mvn -B test'
          }

          post {
            always {
              script {
                maybeArchiveJUnitReports()
              }
            }
          }
        }

        stage('Sonar analysis') {
          when {
            expression {
              return params.RUN_SONAR
            }
          }

          steps {
            sh "mvn -B -U install sonar:sonar -Dsonar.projectKey=${env.SONAR_PROJECT_KEY} -Dsonar.organization=${env.SONAR_ORGANIZATION} -Dsonar.login=${env.SONAR_TOKEN} -Dsonar.scm.provider=git -Dsonar.host.url=${env.SONAR_HOST_URL}"
          }
        }

        stage('deploy & package') {
          steps {
            sh 'mvn -B -DskipTests=true clean deploy package' 
            archiveArtifacts 'iam-login-service/target/iam-login-service.war'
            archiveArtifacts 'iam-login-service/target/classes/iam.version.properties'
            archiveArtifacts 'iam-test-client/target/iam-test-client.jar'
            stash includes: 'iam-login-service/target/iam-login-service.war,iam-login-service/target/classes/iam.version.properties,iam-test-client/target/iam-test-client.jar', name: 'iam-artifacts'
          }
        }
      }
    }
  }

  post {
    success {
      slackSend channel: "#iam", color: 'good', message: "${env.JOB_NAME} - #${env.BUILD_NUMBER} Success (<${env.BUILD_URL}|Open>)" 
    }

    unstable {
      slackSend channel: "#iam", color: 'danger', message: "${env.JOB_NAME} - #${env.BUILD_NUMBER} Unstable (<${env.BUILD_URL}|Open>)" 
    }

    failure {
      slackSend channel: "#iam", color: 'danger', message: "${env.JOB_NAME} - #${env.BUILD_NUMBER} Failure (<${env.BUILD_URL}|Open>)" 
    }
  }
}
