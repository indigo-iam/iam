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
package it.infn.mw.iam.core.web.multi_factor_authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.Logo;

import com.google.common.base.Strings;

@Component
public class DefaultMultiFactorVerificationPageConfiguration
    implements MultiFactorVerificationPageConfiguration {

  private final IamProperties iamProperties;

  public static final String DEFAULT_VERIFICATION_BUTTON_TEXT = "Verify";

  @Autowired
  public DefaultMultiFactorVerificationPageConfiguration(IamProperties properties) {
    this.iamProperties = properties;
  }

  @Override
  public Logo getLogo() {
    return iamProperties.getLogo();
  }

  @Override
  public String getVerifyButtonText() {
    if (Strings.isNullOrEmpty(iamProperties.getVerifyButton().getText())) {
      return DEFAULT_VERIFICATION_BUTTON_TEXT;
    }
    return iamProperties.getVerifyButton().getText();
  }

}
