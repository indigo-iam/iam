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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

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
 * External resources configured under <code>iam.protected-resources</code> are served at
 * <code>/protected-resource-metadata/{id}</code>. That URL is not derived from the resource
 * identifier, so those resources must advertise it in the <code>resource_metadata</code> parameter
 * of their <code>WWW-Authenticate</code> challenges (RFC 9728, Section 5).
 */
@RestController
public class ProtectedResourceMetadataEndpoint {

  public static final String PROTECTED_RESOURCE_URL = ".well-known/oauth-protected-resource";
  public static final String HOSTED_METADATA_URL = "protected-resource-metadata";

  private static final List<String> BEARER_METHODS = List.of("header");
  private static final Set<String> VALID_BEARER_METHODS = Set.of("header", "body", "query");
  private static final Pattern VALID_ID = Pattern.compile("[A-Za-z0-9._-]+");

  private final IamProperties properties;
  private final WellKnownInfoProvider wellKnownInfoProvider;
  private final Map<String, ProtectedResourceProperties> hostedResources;

  public ProtectedResourceMetadataEndpoint(IamProperties properties,
      WellKnownInfoProvider wellKnownInfoProvider) {
    this.properties = properties;
    this.wellKnownInfoProvider = wellKnownInfoProvider;
    this.hostedResources = validate(properties.getProtectedResources());
  }

  public static String resourceIdentifier(IamProperties properties) {
    String baseUrl = properties.getBaseUrl();
    return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
  }

  public static String metadataUrl(IamProperties properties) {
    return String.format("%s/%s", resourceIdentifier(properties), PROTECTED_RESOURCE_URL);
  }

  private static Map<String, ProtectedResourceProperties> validate(
      List<ProtectedResourceProperties> resources) {

    Map<String, ProtectedResourceProperties> byId = new LinkedHashMap<>();

    for (ProtectedResourceProperties r : resources) {
      String id = r.getId();
      if (id == null || !VALID_ID.matcher(id).matches()) {
        throw new IllegalArgumentException(String.format(
            "Invalid iam.protected-resources id '%s': use letters, digits, '.', '_' or '-'", id));
      }
      if (byId.containsKey(id)) {
        throw new IllegalArgumentException(
            String.format("Duplicate iam.protected-resources id '%s'", id));
      }
      validateResourceIdentifier(id, r.getResource());
      if (!VALID_BEARER_METHODS.containsAll(r.getBearerMethods())) {
        throw new IllegalArgumentException(String.format(
            "Invalid bearer-methods for iam.protected-resources '%s': allowed values are %s", id,
            VALID_BEARER_METHODS));
      }
      byId.put(id, r);
    }
    return byId;
  }

  private static void validateResourceIdentifier(String id, String resource) {
    String error = null;
    if (resource == null) {
      error = "resource is required";
    } else {
      try {
        URI uri = new URI(resource);
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !"http".equalsIgnoreCase(uri.getScheme())
            || uri.getHost() == null) {
          error = "resource must be an absolute http(s) URL";
        } else if (uri.getRawFragment() != null) {
          error = "resource must not contain a fragment";
        }
      } catch (URISyntaxException e) {
        error = "resource is not a valid URL";
      }
    }
    if (error != null) {
      throw new IllegalArgumentException(
          String.format("Invalid iam.protected-resources '%s': %s", id, error));
    }
  }

  @GetMapping(value = {"/" + PROTECTED_RESOURCE_URL})
  public ProtectedResourceMetadata protectedResourceMetadata() {

    WellKnownConfiguration asConfig = wellKnownInfoProvider.getWellKnownInfo();

    return new ProtectedResourceMetadata(resourceIdentifier(properties),
        List.of(properties.getIssuer()), asConfig.scopesSupported(), BEARER_METHODS,
        properties.getTopbarTitle(), null, asConfig.opPolicyUri(), asConfig.opTosUri());
  }

  @GetMapping(value = {"/" + HOSTED_METADATA_URL + "/{id}"})
  public ProtectedResourceMetadata hostedProtectedResourceMetadata(@PathVariable String id) {

    ProtectedResourceProperties r = hostedResources.get(id);
    if (r == null) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND,
          String.format("Protected resource '%s' not found", id));
    }

    return new ProtectedResourceMetadata(r.getResource(), List.of(properties.getIssuer()),
        new LinkedHashSet<>(r.getScopes()), r.getBearerMethods(), r.getName(),
        r.getDocumentation(), r.getPolicyUri(), r.getTosUri());
  }
}
