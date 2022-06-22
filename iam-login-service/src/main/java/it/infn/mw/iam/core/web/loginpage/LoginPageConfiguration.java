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
package it.infn.mw.iam.core.web.loginpage;

import java.util.List;
import java.util.Optional;

import it.infn.mw.iam.config.IamProperties.Logo;
import it.infn.mw.iam.config.oidc.OidcProvider;

public interface LoginPageConfiguration {

  boolean isShowRegistrationButton();

  boolean isLocalAuthenticationVisible();

  boolean isShowLinkToLocalAuthenticationPage();

  boolean isExternalAuthenticationEnabled();

  boolean isOidcEnabled();

  boolean isGithubEnabled();

  boolean isSamlEnabled();

  boolean isRegistrationEnabled();

  boolean isAccountLinkingEnabled();

  boolean isIncludeCustomContent();

  String getCustomContentUrl();

  Optional<String> getPrivacyPolicyUrl();

  String getPrivacyPolicyText();

  String getLoginButtonText();

  List<OidcProvider> getOidcProviders();

  Logo getLogo();

}
