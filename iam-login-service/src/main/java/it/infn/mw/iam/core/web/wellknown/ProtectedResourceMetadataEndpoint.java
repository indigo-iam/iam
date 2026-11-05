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

import java.util.LinkedHashSet;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.ProtectedResourceProperties;

/**
 * Publishes OAuth 2.0 Protected Resource Metadata (RFC 9728).
 *
 * IAM's own bearer-protected APIs (SCIM, IAM APIs, userinfo, client registration) are described at
 * the well-known location. The resource identifier is the IAM base URL, so the metadata URL is
 * obtained by appending the well-known suffix to the host, as required by RFC 9728, Section 3.1.
 *
 * External resources configured under <code>iam.protected-resources</code> (or in
 * <code>iam.protected-resources-file</code>, see {@link ProtectedResourceRegistry}) are served at
 * <code>/protected-resource-metadata/{id}</code>. That URL is not derived from the resource
 * identifier, so those resources must advertise it in the <code>resource_metadata</code> parameter
 * of their <code>WWW-Authenticate</code> challenges (RFC 9728, Section 5).
 */
@RestController
public class ProtectedResourceMetadataEndpoint {

  public static final String PROTECTED_RESOURCE_URL = ProtectedResources.PROTECTED_RESOURCE_URL;
  public static final String HOSTED_METADATA_URL = "protected-resource-metadata";

  private static final List<String> BEARER_METHODS = List.of("header");

  private final IamProperties properties;
  private final WellKnownInfoProvider wellKnownInfoProvider;
  private final ProtectedResourceRegistry registry;

  public ProtectedResourceMetadataEndpoint(IamProperties properties,
      WellKnownInfoProvider wellKnownInfoProvider, ProtectedResourceRegistry registry) {
    this.properties = properties;
    this.wellKnownInfoProvider = wellKnownInfoProvider;
    this.registry = registry;
  }

  @GetMapping(value = {"/" + PROTECTED_RESOURCE_URL})
  public ProtectedResourceMetadata protectedResourceMetadata() {

    WellKnownConfiguration asConfig = wellKnownInfoProvider.getWellKnownInfo();

    return new ProtectedResourceMetadata(ProtectedResources.iamResourceIdentifier(properties),
        List.of(properties.getIssuer()), asConfig.scopesSupported(), BEARER_METHODS,
        properties.getTopbarTitle(), null, asConfig.opPolicyUri(), asConfig.opTosUri());
  }

  @GetMapping(value = {"/" + HOSTED_METADATA_URL + "/{id}"})
  public ProtectedResourceMetadata hostedProtectedResourceMetadata(@PathVariable String id) {

    ProtectedResourceProperties r = registry.findById(id)
      .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
          String.format("Protected resource '%s' not found", id)));

    return new ProtectedResourceMetadata(r.getResource(), List.of(properties.getIssuer()),
        new LinkedHashSet<>(r.getScopes()), r.getBearerMethods(), r.getName(),
        r.getDocumentation(), r.getPolicyUri(), r.getTosUri());
  }
}
