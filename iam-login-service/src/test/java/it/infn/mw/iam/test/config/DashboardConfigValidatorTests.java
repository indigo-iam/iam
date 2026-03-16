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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import javax.validation.ConstraintValidatorContext;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import it.infn.mw.iam.api.client.management.validation.DashboardConfigValidator;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;

class DashboardConfigValidatorTests {

  private final DashboardConfigValidator validator = new DashboardConfigValidator();
  private final ConstraintValidatorContext context = mock(ConstraintValidatorContext.class);
  private static DashboardProperties dashboardProperties;

  @BeforeEach
  void setup() {
    dashboardProperties = new DashboardProperties();
    dashboardProperties.setEnabled(true);
    dashboardProperties.setClientId("client-dashboard");
    dashboardProperties.setClientSecret("0tlkqGPJD2vWN1dgTqi3xn-PAJ7EMgNKFFUOydZPsTLkIouqQFmfioJcvfk0V2Xt");
  }

  @Test
  void testSkipValidation() {
    dashboardProperties = new DashboardProperties();
    dashboardProperties.setEnabled(false);
    dashboardProperties.setClientId(null);
    dashboardProperties.setClientSecret(null);
    assertTrue(validator.isValid(dashboardProperties, context));
  }

  @Test
  void testDashboardPropertiesValid() {
    assertTrue(validator.isValid(dashboardProperties, context));
  }

  @Test
  void testIsNotValidDashboardSecret() {
    invalidSecret("too-short-client-secret");
    invalidSecret("too-long-client-secret-82gbV6OEwGBCPMmcFPXg5-4wRJXnKc-4wds5odwrFiY4wds5odwrF");
    invalidSecret("0tlkqGPJD2vWN1/dgTqi3xn-PAJ7EMgNKFFUOydZPsTLkIouqQFmfioJcvfk0V2Xt");
    invalidSecret(null);
    invalidSecret("");
  }

  @Test
  void testIsNotValidDashboardClientIdNull() {
    invalidClientId(null);
    invalidClientId("id");
    invalidClientId("client-with-special-chars/");
    invalidClientId("client with spaces");
    invalidClientId("too long client-id over 255 characters " + "a".repeat(256));
    invalidClientId("");
  }

  private void invalidSecret(String secret) {
    dashboardProperties.setClientSecret(secret);
    assertFalse(validator.isValid(dashboardProperties, context));
  }

  private void invalidClientId(String clientId) {
    dashboardProperties.setClientId(clientId);
    assertFalse(validator.isValid(dashboardProperties, context));
  }
}
