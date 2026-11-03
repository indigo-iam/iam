/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2026
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
package it.infn.mw.iam.config.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.core.userinfo.OAuth2AuthenticationScopeResolver;

/**
 * Checks token scopes in the HTTP filter chain before MVC deserializes request bodies.
 *
 * Keep the scope resolution consistent with the controller's
 * {@code @PreAuthorize("#iam.hasScope('scim:write')")} expression.
 */
@Component("iamApiAuthorization")
@SuppressWarnings("deprecation")
public class IamApiAuthorization {

  private final OAuth2AuthenticationScopeResolver scopeResolver;

  public IamApiAuthorization(OAuth2AuthenticationScopeResolver scopeResolver) {
    this.scopeResolver = scopeResolver;
  }

  public boolean hasScope(Authentication authentication, String scope) {
    if (!(authentication instanceof OAuth2Authentication oauth)) {
      return false;
    }

    return scopeResolver.resolveScope(oauth).contains(scope);
  }
}
