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
package it.infn.mw.iam.config.oidc;

import javax.validation.Valid;

import javax.validation.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import it.infn.mw.iam.authn.common.config.ValidatorProperties;
import it.infn.mw.iam.config.login.LoginButtonProperties;

@JsonInclude(Include.NON_EMPTY)
public class OidcProvider {

  @NotBlank
  private String name;
  
  @NotBlank
  private String issuer;
  
  @Valid
  @JsonIgnore
  private OidcClient client;
  
  @Valid
  private LoginButtonProperties loginButton;

  private boolean enabled = true;
  
  @Valid
  private ValidatorProperties validator;
  
  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public OidcClient getClient() {
    return client;
  }

  public void setClient(OidcClient client) {
    this.client = client;
  }

  public LoginButtonProperties getLoginButton() {
    return loginButton;
  }

  public void setLoginButton(LoginButtonProperties loginButton) {
    this.loginButton = loginButton;
  }

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public ValidatorProperties getValidator() {
    return validator;
  }

  public void setValidator(ValidatorProperties validator) {
    this.validator = validator;
  }
  
}
