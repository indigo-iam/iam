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
package it.infn.mw.iam.test.ext_authn.oidc;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;

import it.infn.mw.iam.authn.oidc.configuration.ServerConfigurationService;
import it.infn.mw.iam.authn.oidc.model.ServerConfiguration;

public class StaticServerConfigurationService implements ServerConfigurationService {

  private final Map<String, ServerConfiguration> serverConfigPerIssuer;

  public StaticServerConfigurationService(Map<String, ServerConfiguration> serverConfigPerIssuer) {
    this.serverConfigPerIssuer = new HashMap<>();
    this.serverConfigPerIssuer.putAll(serverConfigPerIssuer);
  }

  public Map<String, ServerConfiguration> getServers() {
    return serverConfigPerIssuer;
  }

  @Override
  public ServerConfiguration getServerConfiguration(String issuer) {
    return serverConfigPerIssuer.get(issuer);
  }

  @PostConstruct
  public void afterPropertiesSet() {
    if (serverConfigPerIssuer == null || serverConfigPerIssuer.isEmpty()) {
      throw new IllegalArgumentException("Servers map cannot be null or empty.");
    }
  }
}
