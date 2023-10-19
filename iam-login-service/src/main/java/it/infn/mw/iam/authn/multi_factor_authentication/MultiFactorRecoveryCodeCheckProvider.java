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

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

/**
 * Grants full authentication by verifying a provided MFA recovery code. Only comes into play in the
 * step-up authentication flow.
 */
public class MultiFactorRecoveryCodeCheckProvider implements AuthenticationProvider {

  private final IamAccountRepository accountRepo;
  private final IamTotpMfaService totpMfaService;

  public MultiFactorRecoveryCodeCheckProvider(IamAccountRepository accountRepo,
      IamTotpMfaService totpMfaService) {
    this.accountRepo = accountRepo;
    this.totpMfaService = totpMfaService;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    ExtendedAuthenticationToken token = (ExtendedAuthenticationToken) authentication;

    String recoveryCode = token.getRecoveryCode();
    if (recoveryCode == null) {
      return null;
    }

    IamAccount account = accountRepo.findByUsername(authentication.getName())
      .orElseThrow(() -> new BadCredentialsException("Invalid login details"));

    boolean valid = false;

    try {
      valid = totpMfaService.verifyRecoveryCode(account, recoveryCode);
    } catch (MfaSecretNotFoundException e) {
      throw e;
    }

    if (!valid) {
      throw new BadCredentialsException("Bad recovery code");
    }

    return createSuccessfulAuthentication(token);
  }

  protected Authentication createSuccessfulAuthentication(ExtendedAuthenticationToken token) {
    IamAuthenticationMethodReference otp =
        new IamAuthenticationMethodReference(ONE_TIME_PASSWORD.getValue());
    Set<IamAuthenticationMethodReference> refs = token.getAuthenticationMethodReferences();
    refs.add(otp);
    token.setAuthenticationMethodReferences(refs);

    ExtendedAuthenticationToken newToken = new ExtendedAuthenticationToken(token.getPrincipal(),
        token.getCredentials(), token.getFullyAuthenticatedAuthorities());
    newToken.setAuthenticationMethodReferences(token.getAuthenticationMethodReferences());
    newToken.setAuthenticated(true);

    return newToken;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return authentication.equals(ExtendedAuthenticationToken.class);
  }
}
