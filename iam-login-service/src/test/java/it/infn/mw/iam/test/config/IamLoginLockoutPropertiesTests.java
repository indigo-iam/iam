/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.test.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.validation.BindValidationException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import it.infn.mw.iam.config.IamProperties;

class IamLoginLockoutPropertiesTests {

  private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
    .withConfiguration(AutoConfigurations.of(ValidationAutoConfiguration.class))
    .withUserConfiguration(TestConfig.class);

  @Configuration(proxyBeanMethods = false)
  @EnableConfigurationProperties(IamProperties.class)
  static class TestConfig {
  }

  private ApplicationContextRunner validConfiguration() {

    return contextRunner.withPropertyValues("iam.login-lockout.enabled=true",
        "iam.login-lockout.max-failed-attempts=5", "iam.login-lockout.observation-window=5m",
        "iam.login-lockout.lock-duration=30m");
  }

  @Test
  void bindsValidConfiguration() {

    validConfiguration().run(context -> {
      assertThat(context).hasNotFailed();

      var properties = context.getBean(IamProperties.class).getLoginLockout();

      assertThat(properties.isEnabled()).isTrue();
      assertThat(properties.getMaxFailedAttempts()).isEqualTo(5);
      assertThat(properties.getObservationWindow()).isEqualTo(Duration.ofMinutes(5));
      assertThat(properties.getLockDuration()).isEqualTo(Duration.ofMinutes(30));
    });
  }

  @ParameterizedTest
  @ValueSource(strings = {"iam.login-lockout.max-failed-attempts=0",
      "iam.login-lockout.max-failed-attempts=-1", "iam.login-lockout.observation-window=0s",
      "iam.login-lockout.observation-window=-1s", "iam.login-lockout.lock-duration=0s",
      "iam.login-lockout.lock-duration=-1s"})
  void rejectsInvalidConfigurationWhenEnabled(String invalidProperty) {

    validConfiguration().withPropertyValues(invalidProperty).run(context -> {
      assertThat(context).hasFailed();
      assertThat(context.getStartupFailure()).hasRootCauseInstanceOf(BindValidationException.class)
        .hasStackTraceContaining("configurationValid")
        .hasStackTraceContaining(
            "When login lockout is enabled, max-failed-attempts must be at least 1 "
                + "and observation-window and lock-duration must be strictly positive");
    });
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"iam.login-lockout.observation-window=5m", "iam.login-lockout.lock-duration=30m"})
  void rejectsMissingDurationWhenEnabled(String suppliedDuration) {

    contextRunner
      .withPropertyValues("iam.login-lockout.enabled=true",
          "iam.login-lockout.max-failed-attempts=5", suppliedDuration)
      .run(context -> {
        assertThat(context).hasFailed();
        assertThat(context.getStartupFailure())
          .hasRootCauseInstanceOf(BindValidationException.class)
          .hasStackTraceContaining("configurationValid")
          .hasStackTraceContaining(
              "When login lockout is enabled, max-failed-attempts must be at least 1 "
                  + "and observation-window and lock-duration must be strictly positive");
      });
  }

  @Test
  void acceptsInvalidLockoutValuesWhenDisabled() {

    contextRunner
      .withPropertyValues("iam.login-lockout.enabled=false",
          "iam.login-lockout.max-failed-attempts=0", "iam.login-lockout.observation-window=0s",
          "iam.login-lockout.lock-duration=-1s")
      .run(context -> {
        assertThat(context).hasNotFailed();
        assertThat(context.getBean(IamProperties.class).getLoginLockout().isEnabled()).isFalse();
      });
  }

  @Test
  void acceptsMissingLockoutValuesWhenDisabled() {

    contextRunner.withPropertyValues("iam.login-lockout.enabled=false")
      .run(context -> assertThat(context).hasNotFailed());
  }
}
