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
package it.infn.mw.iam.api.config;

import java.util.List;

import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcValidatedProviders;
import it.infn.mw.iam.config.saml.IamSamlLoginShortcut;
import it.infn.mw.iam.config.saml.IamSamlProperties;

@Component
@Endpoint(id = "config")
public class ActuatorConfigEndpoint {

  public static final String CACHE_NAME = "actuator-config";

  private final List<IamSamlLoginShortcut> samlProviders;
  private final List<OidcProvider> oidcProviders;
  private final IamProperties iamProperties;

  public ActuatorConfigEndpoint(OidcValidatedProviders oidcProviders,
      IamSamlProperties samlProperties, IamProperties iamProperties) {
    this.oidcProviders = oidcProviders.getValidatedProviders();
    this.iamProperties = iamProperties;
    this.samlProviders = samlProperties.getLoginShortcuts();
  }

  @ReadOperation
  @Cacheable(CACHE_NAME)
  public ActuatorConfigResponse getIamConfiguration() {
    return new ActuatorConfigResponse(iamProperties, oidcProviders, samlProviders);
  }
}
