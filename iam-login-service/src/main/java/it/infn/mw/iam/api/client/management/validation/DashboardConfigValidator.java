
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
package it.infn.mw.iam.api.client.management.validation;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.config.IamProperties.DashboardProperties;

@Component
@Scope("prototype")
public class DashboardConfigValidator
    implements ConstraintValidator<ValidDashboard, DashboardProperties> {

  private static final String CLIENT_ID_REGEX = "^[a-zA-Z0-9\\-._~]{4,256}$";
  private static final String CLIENT_SECRET_REGEX = "^[a-zA-Z0-9\\-._~]{32,72}$";

  @Override
  public boolean isValid(DashboardProperties dashboardProperties,
      ConstraintValidatorContext context) {

    if (dashboardProperties == null || !dashboardProperties.isEnabled()) {
      return true;
    }

    boolean valid = true;

    context.disableDefaultConstraintViolation();

    if (dashboardProperties.getClientId() == null || dashboardProperties.getClientId().isBlank()) {
      addViolation(context, "dashboard.clientId is required when dashboard is enabled", "clientId");
      valid = false;

    } else if (!dashboardProperties.getClientId().matches(CLIENT_ID_REGEX)) {
      addViolation(context,
          "dashboard.clientId must be 4–256 characters and contain only letters, numbers, '-', '.', '_' or '~'",
          "clientId");
      valid = false;
    }

    if (dashboardProperties.getClientSecret() == null
        || dashboardProperties.getClientSecret().isBlank()) {
      addViolation(context, "dashboard.clientSecret is required when dashboard is enabled",
          "clientSecret");
      valid = false;

    } else if (!dashboardProperties.getClientSecret().matches(CLIENT_SECRET_REGEX)) {
      addViolation(context,
          "dashboard.clientSecret must be 32–72 characters and contain only letters, numbers, '-', '.', '_' or '~'",
          "clientSecret");
      valid = false;
    }

    return valid;
  }

  private void addViolation(ConstraintValidatorContext context, String message, String property) {

    context.buildConstraintViolationWithTemplate(message)
      .addPropertyNode(property)
      .addConstraintViolation();
  }
}
