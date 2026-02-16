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
package it.infn.mw.iam.authn.oidc.configuration;

import java.util.HashMap;
import java.util.Map;

import it.infn.mw.iam.authn.oidc.RegisteredClient;

public class StaticClientConfigurationService implements ClientConfigurationService {

  private final Map<String, RegisteredClient> clients;

  public Map<String, RegisteredClient> getClients() {
    return clients;
  }

  public StaticClientConfigurationService(Map<String, RegisteredClient> clients) {

    if (clients == null || clients.isEmpty()) {
      throw new IllegalArgumentException("Clients map cannot be null or empty");
    }
    this.clients = new HashMap<>();
    this.clients.putAll(clients);
  }

  @Override
  public RegisteredClient getClientConfiguration(String issuer) {

    return clients.get(issuer);
  }
}

