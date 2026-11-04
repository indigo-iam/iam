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

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.config.IamProperties;

/**
 * Publishes the OAuth 2.0 Protected Resource Metadata (RFC 9728) for the APIs IAM itself protects
 * with bearer tokens (SCIM, IAM APIs, userinfo, client registration).
 *
 * The resource identifier is the IAM base URL, so the metadata URL is obtained by appending the
 * well-known suffix to the host, as required by RFC 9728, Section 3.1.
 */
@RestController
public class ProtectedResourceMetadataEndpoint {

  public static final String PROTECTED_RESOURCE_URL = ".well-known/oauth-protected-resource";

  private static final List<String> BEARER_METHODS = List.of("header");

  private final IamProperties properties;
  private final WellKnownInfoProvider wellKnownInfoProvider;

  public ProtectedResourceMetadataEndpoint(IamProperties properties,
      WellKnownInfoProvider wellKnownInfoProvider) {
    this.properties = properties;
    this.wellKnownInfoProvider = wellKnownInfoProvider;
  }

  public static String resourceIdentifier(IamProperties properties) {
    String baseUrl = properties.getBaseUrl();
    return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
  }

  public static String metadataUrl(IamProperties properties) {
    return String.format("%s/%s", resourceIdentifier(properties), PROTECTED_RESOURCE_URL);
  }

  @GetMapping(value = {"/" + PROTECTED_RESOURCE_URL})
  public ProtectedResourceMetadata protectedResourceMetadata() {

    WellKnownConfiguration asConfig = wellKnownInfoProvider.getWellKnownInfo();

    return new ProtectedResourceMetadata(resourceIdentifier(properties),
        List.of(properties.getIssuer()), asConfig.scopesSupported(), BEARER_METHODS,
        properties.getTopbarTitle(), asConfig.opPolicyUri(), asConfig.opTosUri());
  }
}
