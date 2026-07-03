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

import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadataService.OIDCProviderMetadata;

@SuppressWarnings("java:S2160")
public class PendingOIDCAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = -3039943580483543553L;

  private final Map<String, String> principal;

  private final String subject;
  private final String issuer;
  private final transient OIDCProviderMetadata serverConfiguration;
  private transient JWT idToken;
  private final String accessTokenValue;

  public PendingOIDCAuthenticationToken(String subject, String issuer,
      OIDCProviderMetadata serverConfiguration, JWT idToken, String accessTokenValue) {

    super(List.of());
    this.principal = Map.of("sub", subject, "iss", issuer);

    this.subject = subject;
    this.issuer = issuer;
    this.serverConfiguration = serverConfiguration;
    this.idToken = idToken;
    this.accessTokenValue = accessTokenValue;

    setAuthenticated(false);
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

  public JWT getIdToken() {
    return idToken;
  }

  public OIDCProviderMetadata getWellKnownEndpoint() {
    return serverConfiguration;
  }

  public String getIssuer() {
    return issuer;
  }

}
