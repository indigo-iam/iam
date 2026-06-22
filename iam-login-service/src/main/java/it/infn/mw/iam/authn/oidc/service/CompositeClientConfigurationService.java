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
package it.infn.mw.iam.authn.oidc.service;

import java.util.List;

import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.springframework.security.authentication.AuthenticationServiceException;

import it.infn.mw.iam.authn.oidc.exception.ClientConfigurationNotFoundException;

public class CompositeClientConfigurationService implements ClientConfigurationService {

  private final List<ClientConfigurationService> delegates;

  public CompositeClientConfigurationService(List<ClientConfigurationService> delegates) {
    this.delegates = delegates;
  }

  @Override
  public RegisteredClient getClientConfiguration(ServerConfiguration issuer) {

    for (ClientConfigurationService delegate : delegates) {
      try {
        return delegate.getClientConfiguration(issuer);

      } catch (ClientConfigurationNotFoundException e) {
        // try the next one

      } catch (AuthenticationServiceException e) {
        // federation failure
        throw e;
      }
    }

    throw new ClientConfigurationNotFoundException(
        "No client configuration found for " + issuer.getIssuer());
  }
}
