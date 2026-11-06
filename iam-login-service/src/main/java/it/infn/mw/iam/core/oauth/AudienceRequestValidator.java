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
package it.infn.mw.iam.core.oauth;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.Collection;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import it.infn.mw.iam.core.error.InvalidResourceError;

public class AudienceRequestValidator {

  private final Optional<Supplier<Collection<String>>> allowedResources;
  private final Set<String> forbiddenAudiences;

  public AudienceRequestValidator() {
    this(Optional.empty(), Set.of());
  }

  /**
   * @param allowedResources supplies the only resource indicator values accepted, looked up on
   *        each request; any other value is rejected with <code>invalid_target</code>
   */
  public AudienceRequestValidator(Supplier<Collection<String>> allowedResources) {
    this(Optional.of(allowedResources), Set.of());
  }

  /**
   * @param allowedResources as above, or empty to accept any valid resource indicator
   * @param forbiddenAudiences values that cannot be requested in any of the resource, audience or
   *        aud parameters; they are rejected with <code>invalid_target</code>
   */
  public AudienceRequestValidator(Optional<Supplier<Collection<String>>> allowedResources,
      Set<String> forbiddenAudiences) {
    this.allowedResources = allowedResources;
    this.forbiddenAudiences = Set.copyOf(forbiddenAudiences);
  }

  void validateAndUpdateAudienceRequest(Map<String, String> params) {

    validateResourceRequest(params);
    updateAudienceRequest(params);
  }

  /**
   * Checks the resource indicators in the request, throwing {@link InvalidResourceError} for an
   * invalid or not allowed value.
   */
  public void validateResourceRequest(Map<String, String> params) {

    if (params.containsKey(IamOAuthRequestParameters.RESOURCE_KEY)) {
      List<String> resourceParams =
          splitBySpace(params.get(IamOAuthRequestParameters.RESOURCE_KEY));
      resourceParams.forEach(AudienceRequestValidator::validateUrl);
      resourceParams.forEach(this::validateAllowed);
    }

    // Checked on every audience parameter, otherwise audience=... would bypass the restriction
    IamOAuthRequestParameters.AUD_KEYS.stream()
      .map(params::get)
      .flatMap(value -> splitBySpace(value).stream())
      .filter(forbiddenAudiences::contains)
      .findFirst()
      .ifPresent(aud -> {
        throw new InvalidResourceError("This resource cannot be requested: " + aud);
      });
  }

  void updateAudienceRequest(Map<String, String> params) {

    Optional<String> audience = Optional.ofNullable(getFirstNotEmptyAudience(params));
    audience.ifPresent(aud -> params.put(IamOAuthRequestParameters.AUD_KEY, aud));
  }

  String getAllowedResource(List<String> tokenResourceParams,
      Map<String, String> authzRequestParams) {

    List<String> authzResourceParams =
        splitBySpace(authzRequestParams.get(IamOAuthRequestParameters.RESOURCE_KEY));
    tokenResourceParams.retainAll(authzResourceParams);

    String allowedResource = String.join(" ", tokenResourceParams);
    if (allowedResource.isEmpty()) {
      throw new InvalidResourceError("The requested resource was not originally granted");
    }

    return allowedResource;
  }

  private String getFirstNotEmptyAudience(Map<String, String> params) {
    return IamOAuthRequestParameters.AUD_KEYS.stream()
      .map(params::get)
      .filter(aud -> aud != null && !aud.isEmpty())
      .findFirst()
      .orElse(null);
  }

  private void validateAllowed(String url) {
    allowedResources.filter(allowed -> !allowed.get().contains(url)).ifPresent(allowed -> {
      throw new InvalidResourceError(
          "The requested resource is not a registered protected resource: " + url);
    });
  }

  static void validateUrl(String url) {
    try {
      URI validURI = new URL(url).toURI();

      if (validURI.getRawQuery() != null) {
        throw new InvalidResourceError("The resource indicator contains a query component: " + url);
      }
      if (validURI.getRawFragment() != null) {
        throw new InvalidResourceError(
            "The resource indicator contains a fragment component: " + url);
      }

    } catch (MalformedURLException | URISyntaxException e) {
      throw new InvalidResourceError("Not a valid URI: " + url);
    }
  }

  static List<String> splitBySpace(String str) {
    if (str == null) {
      return new ArrayList<>();
    }
    return Pattern.compile(" ").splitAsStream(str).collect(Collectors.toList());
  }
}