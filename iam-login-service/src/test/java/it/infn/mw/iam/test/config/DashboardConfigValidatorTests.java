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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import it.infn.mw.iam.config.IamProperties.DashboardProperties;

class DashboardConfigValidatorTests {

  private Validator validator;
  private DashboardProperties dashboardProperties;

  @BeforeEach
  void setup() {
    
    ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
    validator = factory.getValidator();

    dashboardProperties = new DashboardProperties();
    dashboardProperties.setEnabled(true);
    dashboardProperties.setClientId("client-dashboard");
    dashboardProperties.setClientSecret(
        "0tlkqGPJD2vWN1dgTqi3xn-PAJ7EMgNKFFUOydZPsTLkIouqQFmfioJcvfk0V2Xt");
  }

  @Test
  void testSkipValidationWhenDisabled() {

    dashboardProperties.setEnabled(false);
    dashboardProperties.setClientId(null);
    dashboardProperties.setClientSecret(null);

    assertTrue(validate().isEmpty());
  }

  @Test
  void testValidDashboardProperties() {

    assertTrue(validate().isEmpty());
  }

  @Test
  void testClientIdRequired() {
    dashboardProperties.setClientId(null);

    assertViolation(
        "dashboard.clientId is required when dashboard is enabled");
  }

  @Test
  void testClientIdInvalidFormat() {
    dashboardProperties.setClientId("bad/id");

    assertViolation(
        "dashboard.clientId must be 4–256 characters and contain only letters, numbers, '-', '.', '_' or '~'");
  }

  @Test
  void testClientSecretRequired() {
    dashboardProperties.setClientSecret(null);

    assertViolation(
        "dashboard.clientSecret is required when dashboard is enabled");
  }

  @Test
  void testClientSecretInvalidFormat() {
    dashboardProperties.setClientSecret("short");

    assertViolation(
        "dashboard.clientSecret must be 32–72 characters and contain only letters, numbers, '-', '.', '_' or '~'");
  }

  @Test
  void testMultipleViolations() {

    dashboardProperties.setClientId("x");
    dashboardProperties.setClientSecret("short");

    Set<String> messages = validateMessages();

    assertEquals(2, messages.size());

    assertTrue(messages.contains(
        "dashboard.clientId must be 4–256 characters and contain only letters, numbers, '-', '.', '_' or '~'"));

    assertTrue(messages.contains(
        "dashboard.clientSecret must be 32–72 characters and contain only letters, numbers, '-', '.', '_' or '~'"));
  }

  private Set<ConstraintViolation<DashboardProperties>> validate() {
    return validator.validate(dashboardProperties);
  }

  private Set<String> validateMessages() {
    return validate().stream()
        .map(ConstraintViolation::getMessage)
        .collect(Collectors.toSet());
  }

  private void assertViolation(String expectedMessage) {
    Set<String> messages = validateMessages();

    assertEquals(1, messages.size());
    assertTrue(messages.contains(expectedMessage));
  }
}
