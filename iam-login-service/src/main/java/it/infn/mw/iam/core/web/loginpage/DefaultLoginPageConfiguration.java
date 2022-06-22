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

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

import com.google.common.base.Strings;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.Logo;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcValidatedProviders;

@Component
public class DefaultLoginPageConfiguration implements LoginPageConfiguration, EnvironmentAware {

  public static final String DEFAULT_PRIVACY_POLICY_TEXT = "Privacy policy";
  public static final String DEFAULT_LOGIN_BUTTON_TEXT = "Sign in";

  private Environment env;

  private boolean oidcEnabled;
  private boolean githubEnabled;
  private boolean samlEnabled;
  private boolean registrationEnabled;
  private boolean localAuthenticationVisible;
  private boolean showLinkToLocalAuthn;

  @Value("${iam.account-linking.enable}")
  private Boolean accountLinkingEnabled;

  private OidcValidatedProviders providers;

  private final IamProperties iamProperties;

  @Autowired
  public DefaultLoginPageConfiguration(OidcValidatedProviders providers, IamProperties properties) {
    this.providers = providers;
    this.iamProperties = properties;
  }


  @PostConstruct
  public void init() {

    oidcEnabled = !providers.getValidatedProviders().isEmpty();
    githubEnabled = env.acceptsProfiles(Profiles.of("github"));
    samlEnabled = env.acceptsProfiles(Profiles.of("saml"));
    registrationEnabled = env.acceptsProfiles(Profiles.of("registration"));
    localAuthenticationVisible = IamProperties.LocalAuthenticationLoginPageMode.VISIBLE
      .equals(iamProperties.getLocalAuthn().getLoginPageVisibility());
    showLinkToLocalAuthn = IamProperties.LocalAuthenticationLoginPageMode.HIDDEN_WITH_LINK
      .equals(iamProperties.getLocalAuthn().getLoginPageVisibility());
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
    return accountLinkingEnabled.booleanValue();
  }

  @Override
  public Optional<String> getPrivacyPolicyUrl() {

    if (Strings.isNullOrEmpty(iamProperties.getPrivacyPolicy().getUrl())) {
      return Optional.empty();
    }

    return Optional.of(iamProperties.getPrivacyPolicy().getUrl());
  }

  @Override
  public String getPrivacyPolicyText() {
    if (Strings.isNullOrEmpty(iamProperties.getPrivacyPolicy().getText())) {
      return DEFAULT_PRIVACY_POLICY_TEXT;
    }
    return iamProperties.getPrivacyPolicy().getText();
  }

  @Override
  public String getLoginButtonText() {
    if (Strings.isNullOrEmpty(iamProperties.getLoginButton().getText())) {
      return DEFAULT_LOGIN_BUTTON_TEXT;
    }
    return iamProperties.getLoginButton().getText();
  }

  @Override
  public List<OidcProvider> getOidcProviders() {
    return providers.getValidatedProviders();
  }

  @Override
  public Logo getLogo() {
    return iamProperties.getLogo();
  }


  @Override
  public boolean isExternalAuthenticationEnabled() {
    return isOidcEnabled() || isSamlEnabled();
  }

  @Override
  public boolean isLocalAuthenticationVisible() {
    return localAuthenticationVisible;
  }


  @Override
  public boolean isShowLinkToLocalAuthenticationPage() {
    return showLinkToLocalAuthn;
  }


  @Override
  public boolean isShowRegistrationButton() {
    return iamProperties.getRegistration().isShowRegistrationButtonInLoginPage();
  }

  public boolean isIncludeCustomContent() {
    return iamProperties.getCustomization().isIncludeCustomLoginPageContent();
  }

  @Override
  public String getCustomContentUrl() {
    return iamProperties.getCustomization().getCustomLoginPageContentUrl();
  }
}
