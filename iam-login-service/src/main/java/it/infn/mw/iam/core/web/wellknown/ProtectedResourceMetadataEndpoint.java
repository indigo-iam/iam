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
package it.infn.mw.iam.core.web.wellknown;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.ProtectedResourceProperties;

@RestController
public class ProtectedResourceMetadataEndpoint {

  public static final String PROTECTED_RESOURCE_URL = ".well-known/oauth-protected-resource";

  // Not under .well-known: RFC 9728 derives that URL from the resource's own host, so external
  // resources must advertise this one in the resource_metadata parameter of their challenges
  public static final String HOSTED_METADATA_URL = "protected-resource-metadata";

  private final IamProperties properties;
  private final WellKnownInfoProvider wellKnownInfoProvider;
  private final ProtectedResourceRegistry registry;

  public ProtectedResourceMetadataEndpoint(IamProperties properties,
      WellKnownInfoProvider wellKnownInfoProvider, ProtectedResourceRegistry registry) {
    this.properties = properties;
    this.wellKnownInfoProvider = wellKnownInfoProvider;
    this.registry = registry;
  }

  @GetMapping("/" + PROTECTED_RESOURCE_URL)
  public ProtectedResourceMetadata protectedResourceMetadata() {

    WellKnownConfiguration asConfig = wellKnownInfoProvider.getWellKnownInfo();

    return new ProtectedResourceMetadata(registry.iamResourceIdentifier(),
        List.of(properties.getIssuer()), asConfig.scopesSupported(), List.of("header"),
        properties.getTopbarTitle(), null, asConfig.opPolicyUri(), asConfig.opTosUri());
  }

  @GetMapping("/" + HOSTED_METADATA_URL + "/{id}")
  public ProtectedResourceMetadata hostedProtectedResourceMetadata(@PathVariable String id) {

    ProtectedResourceProperties r = registry.findById(id)
      .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

    return new ProtectedResourceMetadata(r.getResource(), List.of(properties.getIssuer()),
        r.getScopes(), r.getBearerMethods(), r.getName(), r.getDocumentation(), r.getPolicyUri(),
        r.getTosUri());
  }
}
