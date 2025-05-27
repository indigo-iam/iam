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

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.ONE_TIME_PASSWORD;

import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

/**
 * Grants full authentication by verifying a provided MFA TOTP. Only comes into play in the step-up
 * authentication flow.
 */
public class MultiFactorTotpCheckProvider implements AuthenticationProvider {

  private final IamAccountRepository accountRepo;
  private final IamTotpMfaService totpMfaService;

  public MultiFactorTotpCheckProvider(IamAccountRepository accountRepo,
      IamTotpMfaService totpMfaService) {
    this.accountRepo = accountRepo;
    this.totpMfaService = totpMfaService;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (authentication instanceof ExtendedAuthenticationToken
        || authentication instanceof AbstractExternalAuthenticationToken) {
      return processAuthentication(authentication);
    }
    return null;
  }

  private Authentication processAuthentication(Authentication authentication) {
    String totp = getTotp(authentication);
    if (totp == null) {
      return null;
    }

    IamAccount account = accountRepo.findByUsername(authentication.getName())
      .orElseThrow(() -> new BadCredentialsException("Invalid login details"));

    if (!isValidTotp(account, totp)) {
      throw new BadCredentialsException("Bad TOTP");
    }

    return createSuccessfulAuthentication(authentication);
  }

  private String getTotp(Authentication authentication) {
    if (authentication instanceof ExtendedAuthenticationToken extendedToken) {
      return extendedToken.getTotp();
    } else if (authentication instanceof AbstractExternalAuthenticationToken<?> externalToken) {
      return externalToken.getTotp();
    }
    return null;
  }

  private boolean isValidTotp(IamAccount account, String totp) {
    try {
      return totpMfaService.verifyTotp(account, totp);
    } catch (MfaSecretNotFoundException e) {
      throw new MfaSecretNotFoundException("No multi-factor secret is attached to this account");
    }
  }

  private Authentication createSuccessfulAuthentication(Authentication authentication) {
    IamAuthenticationMethodReference otp =
        new IamAuthenticationMethodReference(ONE_TIME_PASSWORD.getValue());

    Set<IamAuthenticationMethodReference> refs;
    Object principal;
    Object credentials;
    Set<GrantedAuthority> authorities;

    if (authentication instanceof ExtendedAuthenticationToken token) {
      refs = token.getAuthenticationMethodReferences();
      principal = token.getPrincipal();
      credentials = token.getCredentials();
      authorities = token.getFullyAuthenticatedAuthorities();
    } else if (authentication instanceof AbstractExternalAuthenticationToken<?> token) {
      refs = token.getAuthenticationMethodReferences();
      principal = token.getPrincipal();
      credentials = token.getCredentials();
      authorities = token.getFullyAuthenticatedAuthorities();
    } else {
      throw new IllegalArgumentException(
          "Unsupported authentication type: " + authentication.getClass());
    }

    refs.add(otp);

    ExtendedAuthenticationToken newToken =
        new ExtendedAuthenticationToken(principal, credentials, authorities);
    newToken.setAuthenticationMethodReferences(refs);
    newToken.setAuthenticated(true);

    return newToken;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return ExtendedAuthenticationToken.class.isAssignableFrom(authentication)
        || AbstractExternalAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
