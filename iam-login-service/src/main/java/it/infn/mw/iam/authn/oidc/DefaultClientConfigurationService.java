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

import java.util.Optional;

import it.infn.mw.iam.config.oidc.OidcClient;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;

public class DefaultClientConfigurationService implements ClientConfigurationService {

  private final OidcProviderProperties oidcProperties;

  public DefaultClientConfigurationService(OidcProviderProperties oidcProperties) {
    this.oidcProperties = oidcProperties;
  }

  @Override
  public Optional<OidcClient> getClientConfiguration(String issuer) {

    return oidcProperties.getProviders()
      .stream()
      .filter(c -> c.getIssuer().equals(issuer))
      .map(c -> c.getClient())
      .findFirst();
  }

}
