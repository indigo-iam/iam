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
package it.infn.mw.iam.test.startup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.properties.ConfigurationPropertiesBindException;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.BindException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import it.infn.mw.iam.config.IamProperties;

class DashboardConfigurationStartupTests {

  private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
    .withConfiguration(AutoConfigurations.of(TestConfiguration.class));

  @Test
  void contextStartsWithValidDashboardConfiguration() {
    contextRunner
      .withPropertyValues("iam.dashboard.enabled=true",
          "iam.dashboard.client-id=dashboard-client",
          "iam.dashboard.client-secret=abcdefghijklmnopqrstuvwxyz123456")
      .run(context -> {
        assertNull(context.getStartupFailure());
        assertEquals(1, context.getBeanNamesForType(IamProperties.class).length);
      });
  }

  @Test
  void contextStartsWhenDashboardDisabled() {
    contextRunner.withPropertyValues("iam.dashboard.enabled=false")
      .run(context -> assertNull(context.getStartupFailure()));
  }

  @Test
  void contextFailsWhenClientIdMissing() {
    assertValidationFailure("dashboard.clientId is required when dashboard is enabled",
        "iam.dashboard.enabled=true",
        "iam.dashboard.client-secret=abcdefghijklmnopqrstuvwxyz123456");
  }

  @Test
  void contextFailsWhenClientIdBlank() {
    assertValidationFailure("dashboard.clientId is required when dashboard is enabled",
        "iam.dashboard.enabled=true",
        "iam.dashboard.client-id=", "iam.dashboard.client-secret=abcdefghijklmnopqrstuvwxyz123456");
  }

  @Test
  void contextFailsWhenClientIdTooShort() {
    assertValidationFailure(
        "dashboard.clientId must be 4–256 characters and contain only letters, numbers, '-', '.', '_' or '~'",
        "iam.dashboard.enabled=true",
        "iam.dashboard.client-id=abc",
        "iam.dashboard.client-secret=abcdefghijklmnopqrstuvwxyz123456");
  }

  @Test
  void contextFailsWhenClientIdInvalidCharacters() {
    assertValidationFailure(
        "dashboard.clientId must be 4–256 characters and contain only letters, numbers, '-', '.', '_' or '~'",
        "iam.dashboard.enabled=true",
        "iam.dashboard.client-id=bad/id",
        "iam.dashboard.client-secret=abcdefghijklmnopqrstuvwxyz123456");
  }

  @Test
  void contextFailsWhenClientIdContainsSpaces() {
    assertValidationFailure(
        "dashboard.clientId must be 4–256 characters and contain only letters, numbers, '-', '.', '_' or '~'",
        "iam.dashboard.enabled=true",
        "iam.dashboard.client-id=bad client",
        "iam.dashboard.client-secret=abcdefghijklmnopqrstuvwxyz123456");
  }

  @Test
  void contextFailsWhenClientIdTooLong() {
    assertValidationFailure(
        "dashboard.clientId must be 4–256 characters and contain only letters, numbers, '-', '.', '_' or '~'",
        "iam.dashboard.enabled=true",
        "iam.dashboard.client-id=" + "a".repeat(257),
        "iam.dashboard.client-secret=abcdefghijklmnopqrstuvwxyz123456");
  }

  @Test
  void contextFailsWhenClientSecretMissing() {
    assertValidationFailure("dashboard.clientSecret is required when dashboard is enabled",
        "iam.dashboard.enabled=true",
        "iam.dashboard.client-id=dashboard-client");
  }

  @Test
  void contextFailsWhenClientSecretBlank() {
    assertValidationFailure("dashboard.clientSecret is required when dashboard is enabled",
        "iam.dashboard.enabled=true",
        "iam.dashboard.client-id=dashboard-client", "iam.dashboard.client-secret=");
  }

  @Test
  void contextFailsWhenClientSecretTooShort() {
    assertValidationFailure(
        "dashboard.clientSecret must be 32–72 characters and contain only letters, numbers, '-', '.', '_' or '~'",
        "iam.dashboard.enabled=true",
        "iam.dashboard.client-id=dashboard-client", "iam.dashboard.client-secret=short");
  }

  @Test
  void contextFailsWhenClientSecretTooLong() {
    assertValidationFailure(
        "dashboard.clientSecret must be 32–72 characters and contain only letters, numbers, '-', '.', '_' or '~'",
        "iam.dashboard.enabled=true",
        "iam.dashboard.client-id=dashboard-client",
        "iam.dashboard.client-secret=" + "a".repeat(73));
  }

  @Test
  void contextFailsWhenClientSecretContainsInvalidCharacters() {
    assertValidationFailure(
        "dashboard.clientSecret must be 32–72 characters and contain only letters, numbers, '-', '.', '_' or '~'",
        "iam.dashboard.enabled=true",
        "iam.dashboard.client-id=dashboard-client",
        "iam.dashboard.client-secret=abcdefghijklmnopqrstuvwx/1234567890");
  }

  private void assertValidationFailure(String expectedMessage, String... properties) {
    contextRunner.withPropertyValues(properties).run(context -> {
      assertNotNull(context.getStartupFailure());

      Throwable startupFailure = context.getStartupFailure();
      assertNotNull(startupFailure);
      assertTrue(startupFailure instanceof ConfigurationPropertiesBindException);

      Throwable bindException = startupFailure.getCause();
      assertTrue(bindException instanceof BindException);

      Throwable validationException = bindException.getCause();
      assertTrue(validationException.getMessage().contains(expectedMessage));
    });
  }

  @Configuration
  @EnableConfigurationProperties(IamProperties.class)
  static class TestConfiguration {

    @Bean
    LocalValidatorFactoryBean validator() {
      return new LocalValidatorFactoryBean();
    }
  }
}
