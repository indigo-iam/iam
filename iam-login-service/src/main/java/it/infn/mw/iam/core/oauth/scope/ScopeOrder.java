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
package it.infn.mw.iam.core.oauth.scope;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;

/** Reorders already authorized scopes without changing the authorization decision. */
@SuppressWarnings("deprecation")
public class ScopeOrder {

  private ScopeOrder() {}

  public static Set<String> fromRaw(String rawScopes, Set<String> authorized) {
    LinkedHashSet<String> result = new LinkedHashSet<>();
    if (rawScopes != null && !rawScopes.isBlank()) {
      Arrays.stream(rawScopes.trim().split("\\s+"))
        .filter(authorized::contains)
        .forEach(result::add);
    }
    authorized.stream().sorted().forEach(result::add);
    return result;
  }

  public static Set<String> forAuthentication(OAuth2Authentication authentication,
      Set<String> authorized) {
    String rawScopes = null;
    if (authentication.getOAuth2Request().isRefresh()) {
      TokenRequest refresh = authentication.getOAuth2Request().getRefreshTokenRequest();
      if (refresh != null && refresh.getRequestParameters() != null) {
        rawScopes = refresh.getRequestParameters().get("scope");
      }
    }
    if (rawScopes == null && authentication.getOAuth2Request().getRequestParameters() != null) {
      rawScopes = authentication.getOAuth2Request().getRequestParameters().get("scope");
    }
    return fromRaw(rawScopes, authorized);
  }

  public static String serialize(Set<String> scopes) {
    return scopes.stream().collect(Collectors.joining(" "));
  }
}
