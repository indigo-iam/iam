
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
import it.infn.mw.iam.api.client.management.validation.ValidDashboard;

@Component
@Scope("prototype")
public class DashboardConfigValidator implements ConstraintValidator<ValidDashboard, DashboardProperties> {

  private static final String CLIENT_ID_REGEX = "^[a-zA-Z0-9\\-._~]{3,64}$";
  private static final String CLIENT_SECRET_REGEX = "^[a-zA-Z0-9\\-._~]{32,72}$";
  private static final String URL_REGEX = "^(https?://)?([\\w.-]+)(:[0-9]+)?(/.*)?$";

  @Override
  public boolean isValid(DashboardProperties dashboardProperties, ConstraintValidatorContext context) {
    if (dashboardProperties == null || !dashboardProperties.isEnabled()) {
      return true;
    }
    boolean validClientId = dashboardProperties.getClientId() != null
        && dashboardProperties.getClientId().matches(CLIENT_ID_REGEX);
    boolean validClientSecret = dashboardProperties.getClientSecret() != null
        && dashboardProperties.getClientSecret().matches(CLIENT_SECRET_REGEX);
    boolean validUrl = dashboardProperties.getClientBaseUrl() != null
        && dashboardProperties.getClientBaseUrl().matches(URL_REGEX);

    return validClientId && validClientSecret && validUrl;
  }
}