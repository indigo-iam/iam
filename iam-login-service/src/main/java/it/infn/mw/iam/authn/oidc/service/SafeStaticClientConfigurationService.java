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

import java.util.Map;

import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;

import it.infn.mw.iam.authn.oidc.exception.ClientConfigurationNotFoundException;

public class SafeStaticClientConfigurationService implements ClientConfigurationService {

  private final Map<String, RegisteredClient> clients;

  public SafeStaticClientConfigurationService(Map<String, RegisteredClient> clients) {
    this.clients = clients;
  }

  @Override
  public RegisteredClient getClientConfiguration(ServerConfiguration issuer) {
    RegisteredClient rc = clients.get(issuer.getIssuer());

    if (rc == null) {
      throw new ClientConfigurationNotFoundException(
          "No static client for issuer " + issuer.getIssuer());
    }
    return rc;
  }
}
