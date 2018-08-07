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
package it.infn.mw.iam.api.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

import it.infn.mw.iam.config.oidc.OidcClient;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;

@Service
public class DefaultOidcConfigurationService implements OidcConfigurationService {

  private static final String FAKE_VALUE = "define_me_please";

  private OidcProviderProperties oidcProviderConfiguration;

  @Autowired
  public DefaultOidcConfigurationService(OidcProviderProperties oidcProviderConfiguration) {
    this.oidcProviderConfiguration = oidcProviderConfiguration;
  }

  @Override
  public List<OidcProvider> getOidcProviders() {
    List<OidcProvider> oidcProviders = new ArrayList<>();
    for (OidcProvider provider : oidcProviderConfiguration.getProviders()) {
      if (isValidProvider(provider)) {
        OidcProvider elem = new OidcProvider();
        elem.setIssuer(provider.getIssuer());
        elem.setName(provider.getName());
        elem.setLoginButton(provider.getLoginButton());
        oidcProviders.add(elem);
      }
    }
    return oidcProviders;
  }

  private boolean isValidProvider(OidcProvider provider) {
    return isValidIssuer(provider.getIssuer()) && provider.getClient() != null
        && isValidClient(provider.getClient());
  }

  private boolean isValidIssuer(String issuer) {
    return !Strings.isNullOrEmpty(issuer);
  }

  private boolean isValidClient(OidcClient client) {
    return !(Strings.isNullOrEmpty(client.getClientId()) || FAKE_VALUE.equals(client.getClientId())
        || Strings.isNullOrEmpty(client.getClientSecret())
        || FAKE_VALUE.equals(client.getClientSecret()));
  }
}
