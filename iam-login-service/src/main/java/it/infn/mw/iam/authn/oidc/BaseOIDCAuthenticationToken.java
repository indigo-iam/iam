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
package it.infn.mw.iam.authn.oidc;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.nimbusds.jwt.JWT;

@SuppressWarnings("java:S2160")
public abstract class BaseOIDCAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = 4401589569842096551L;

  private final Map<String, String> principal;
  private final String subject;
  private final String issuer;
  private transient JWT idToken;
  private final String accessTokenValue;

  protected BaseOIDCAuthenticationToken(String subject, String issuer,
      Collection<? extends GrantedAuthority> authorities, JWT idToken, String accessTokenValue) {

    super(authorities);

    this.principal = Map.of("sub", subject, "iss", issuer);
    this.subject = subject;
    this.issuer = issuer;
    this.idToken = idToken;
    this.accessTokenValue = accessTokenValue;
  }

  @Override
  public Object getCredentials() {
    return accessTokenValue;
  }

  @Override
  public Object getPrincipal() {
    return principal;
  }

  public String getSub() {
    return subject;
  }

  public String getIssuer() {
    return issuer;
  }

  public JWT getIdToken() {
    return idToken;
  }

}
