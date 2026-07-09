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

import com.nimbusds.jwt.JWT;

@SuppressWarnings("java:S2160")
public class PendingOIDCAuthenticationToken extends BaseOIDCAuthenticationToken {

  private static final long serialVersionUID = -3039943580483543553L;

  private final transient OIDCProviderMetadata serverConfiguration;

  public PendingOIDCAuthenticationToken(String subject, String issuer,
      OIDCProviderMetadata serverConfiguration, JWT idToken, String accessTokenValue) {

    super(subject, issuer, List.of(), idToken, accessTokenValue);

    this.serverConfiguration = serverConfiguration;

    setAuthenticated(false);
  }

  public OIDCProviderMetadata getWellKnownEndpoint() {
    return serverConfiguration;
  }
}
