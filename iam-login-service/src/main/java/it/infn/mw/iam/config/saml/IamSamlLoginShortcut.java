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
package it.infn.mw.iam.config.saml;

import javax.validation.Valid;

import javax.validation.constraints.NotBlank;

import it.infn.mw.iam.config.login.LoginButtonProperties;

public class IamSamlLoginShortcut {
  
  @NotBlank
  private String name;
  
  @NotBlank
  private String entityId;
  
  @Valid
  private LoginButtonProperties loginButton;
  
  private boolean enabled = true;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getEntityId() {
    return entityId;
  }

  public void setEntityId(String entityId) {
    this.entityId = entityId;
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
  
}
