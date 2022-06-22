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
package it.infn.mw.iam.api.config;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.PrivacyPolicy;
import it.infn.mw.iam.config.IamProperties.UserProfileProperties;
import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.config.login.LoginButtonProperties;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcValidatedProviders;
import it.infn.mw.iam.config.saml.IamSamlLoginShortcut;
import it.infn.mw.iam.config.saml.IamSamlProperties;

@RestController
@RequestMapping("/iam/config")
public class ConfigurationController {

  private final List<IamSamlLoginShortcut> loginShortcuts;
  private final LoginButtonProperties wayfLoginButton;
  private final OidcValidatedProviders providers;
  private final IamProperties iamProperties;
  private final LifecycleProperties lifecycleProperties;

  @Autowired
  public ConfigurationController(OidcValidatedProviders providers, IamSamlProperties samlProps,
      IamProperties iamProperties, LifecycleProperties lifecycleProperties) {
    this.providers = providers;
    this.loginShortcuts = samlProps.getLoginShortcuts();
    this.wayfLoginButton = samlProps.getWayfLoginButton();
    this.iamProperties = iamProperties;
    this.lifecycleProperties = lifecycleProperties;
  }

  @RequestMapping(method = GET, value = "/oidc/providers")
  public List<OidcProvider> listProviders() {
    return providers.getValidatedProviders();
  }

  @RequestMapping(method = GET, value = "/saml/shortcuts")
  public List<IamSamlLoginShortcut> listSamlLoginShortcuts() {
    return loginShortcuts;
  }

  @RequestMapping(method = GET, value = "/saml/wayf-login-button")
  public LoginButtonProperties listWayfLoginButton() {
    return wayfLoginButton;
  }

  @RequestMapping(method = GET, value = "/privacy-policy")
  public PrivacyPolicy privacyPolicyURL() {
    return iamProperties.getPrivacyPolicy();
  }

  @RequestMapping(method = GET, value = "/profile")
  public UserProfileProperties profileProperties() {
    return iamProperties.getUserProfile();
  }

  @RequestMapping(method = GET, value = "/lifecycle/account/read-only-end-time")
  public boolean readOnlyAccountEndTime() {
    return lifecycleProperties.getAccount().isReadOnlyEndTime();
  }
}
