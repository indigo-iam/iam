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
package it.infn.mw.iam.config.oidc;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(Include.NON_EMPTY)
@Component
public class OidcProvider {

  private String name;
  private String issuer;
  private OidcClient client;
  private OidcLoginButton loginButton;

  public OidcProvider() {
    // empty constructor
  }

  @JsonCreator
  public OidcProvider(@JsonProperty("name") String name, @JsonProperty("issuer") String issuer,
      @JsonProperty("loginButton") OidcLoginButton loginButton) {
    super();
    this.name = name;
    this.issuer = issuer;
    this.loginButton = loginButton;
  }


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

  public OidcLoginButton getLoginButton() {
    return loginButton;
  }

  public void setLoginButton(OidcLoginButton loginButton) {
    this.loginButton = loginButton;
  }
}
