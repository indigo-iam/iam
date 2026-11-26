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
package it.infn.mw.iam.core.oauth.granters;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.IamLocalAuthenticationProvider;

/** Applies local login policy to the single-step password grant. */
public final class PasswordGrantAuthenticationProvider implements AuthenticationProvider {

  private final IamLocalAuthenticationProvider localProvider;

  public PasswordGrantAuthenticationProvider(IamLocalAuthenticationProvider localProvider) {
    this.localProvider = localProvider;
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    var request = new ExtendedAuthenticationToken(authentication.getPrincipal(),
        authentication.getCredentials());
    request.setDetails(authentication.getDetails());
    Authentication verified = localProvider.authenticate(request);
    if (!verified.isAuthenticated()) {
      // An intermediate MFA result cannot complete the password grant.
      throw new BadCredentialsException("Bad credentials");
    }

    var result = new UsernamePasswordAuthenticationToken(verified.getPrincipal(), null,
        verified.getAuthorities());
    result.setDetails(verified.getDetails());
    return result;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.equals(authentication);
  }
}
