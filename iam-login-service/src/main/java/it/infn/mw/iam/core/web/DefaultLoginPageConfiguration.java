/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2018
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
package it.infn.mw.iam.core.web;

import static it.infn.mw.iam.api.account_linking.AccountLinkingConstants.ACCOUNT_LINKING_DISABLE_PROPERTY;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import com.google.common.base.Strings;

import it.infn.mw.iam.api.config.OidcConfigurationService;
import it.infn.mw.iam.config.oidc.OidcProvider;

@Component
public class DefaultLoginPageConfiguration implements LoginPageConfiguration, EnvironmentAware {

  public static final String DEFAULT_PRIVACY_POLICY_TEXT = "Privacy policy";
  public static final String DEFAULT_LOGIN_BUTTON_TEXT = "Sign in";

  private Environment env;

  private boolean oidcEnabled;
  private boolean githubEnabled;
  private boolean samlEnabled;
  private boolean registrationEnabled;

  @Value(ACCOUNT_LINKING_DISABLE_PROPERTY)
  private Boolean accountLinkingDisable;

  @Value("${iam.privacyPolicy.url}")
  private String privacyPolicyUrl;

  @Value("${iam.privacyPolicy.text}")
  private String privacyPolicyText;

  @Value("${iam.loginButton.text}")
  private String loginButtonText;

  @Autowired
  private OidcConfigurationService oidcConfService;


  @PostConstruct
  public void init() {

    oidcEnabled = !oidcConfService.getOidcProviders().isEmpty();
    githubEnabled = activeProfilesContains("github");
    samlEnabled = activeProfilesContains("saml");
    registrationEnabled = activeProfilesContains("registration");
  }

  private boolean activeProfilesContains(String val) {

    return Arrays.asList(env.getActiveProfiles()).contains(val);
  }

  @Override
  public boolean isOidcEnabled() {

    return oidcEnabled;
  }

  @Override
  public boolean isGithubEnabled() {

    return githubEnabled;
  }

  @Override
  public boolean isSamlEnabled() {

    return samlEnabled;
  }

  @Override
  public void setEnvironment(Environment environment) {

    this.env = environment;

  }

  @Override
  public boolean isRegistrationEnabled() {

    return registrationEnabled;
  }

  @Override
  public boolean isAccountLinkingEnabled() {
    return !accountLinkingDisable.booleanValue();
  }

  @Override
  public Optional<String> getPrivacyPolicyUrl() {
    if (Strings.isNullOrEmpty(privacyPolicyUrl)) {
      return Optional.empty();
    }

    return Optional.of(privacyPolicyUrl);
  }

  @Override
  public String getPrivacyPolicyText() {
    if (Strings.isNullOrEmpty(privacyPolicyText)) {
      return DEFAULT_PRIVACY_POLICY_TEXT;
    }
    return privacyPolicyText;
  }

  @Override
  public String getLoginButtonText() {
    if (Strings.isNullOrEmpty(loginButtonText)) {
      return DEFAULT_LOGIN_BUTTON_TEXT;
    }
    return loginButtonText;
  }

  @Override
  public List<OidcProvider> getOidcProviders() {
    return oidcConfService.getOidcProviders();
  }

}
