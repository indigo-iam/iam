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
package it.infn.mw.iam.authn.multi_factor_authentication;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;

/**
 * Upgrades a pre-authenticated token to a fully authenticated {@link ExtendedAuthenticationToken}
 * once a second factor has been verified, preserving the principal, the external authentication
 * and the authentication method references collected so far
 */
public final class MultiFactorVerifiedTokenFactory {

  private MultiFactorVerifiedTokenFactory() {
    // prevent instantiation
  }

  public static ExtendedAuthenticationToken create(Authentication authentication,
      IamAuthenticationMethodReference verifiedMethod) {

    Set<IamAuthenticationMethodReference> refs;
    Object principal;
    Object credentials;
    Set<GrantedAuthority> authorities;
    AbstractExternalAuthenticationToken<?> externalAuthentication = null;

    if (authentication instanceof ExtendedAuthenticationToken token) {
      refs = new HashSet<>(token.getAuthenticationMethodReferences());
      principal = token.getPrincipal();
      credentials = token.getCredentials();
      authorities = token.getFullyAuthenticatedAuthorities();
      externalAuthentication = token.getExternalAuthentication();
    } else if (authentication instanceof AbstractExternalAuthenticationToken<?> token) {
      refs = new HashSet<>(token.getAuthenticationMethodReferences());
      principal = token.getPrincipal();
      credentials = token.getCredentials();
      authorities = token.getFullyAuthenticatedAuthorities();
      externalAuthentication = token;
    } else {
      throw new IllegalArgumentException(
          "Unsupported authentication type: " + authentication.getClass());
    }

    refs.add(verifiedMethod);

    ExtendedAuthenticationToken newToken =
        new ExtendedAuthenticationToken(principal, credentials, authorities);
    newToken.setAuthenticationMethodReferences(refs);
    newToken.setAuthenticated(true);
    newToken.setExternalAuthentication(externalAuthentication);
    // Carries the acr claim set by the first-factor providers into the verified authentication
    newToken.setDetails(authentication.getDetails());
    return newToken;
  }
}
