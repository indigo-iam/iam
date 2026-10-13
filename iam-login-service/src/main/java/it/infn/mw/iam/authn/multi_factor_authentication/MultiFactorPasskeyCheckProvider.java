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

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.PASSKEY;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.IamPasskeyService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyException;
import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

/**
 * Grants full authentication by verifying a WebAuthn assertion produced with one of the account
 * passkeys. Only comes into play in the step-up authentication flow
 */
public class MultiFactorPasskeyCheckProvider implements AuthenticationProvider {

  private static final Logger LOG = LoggerFactory.getLogger(MultiFactorPasskeyCheckProvider.class);

  public static final String BAD_PASSKEY_MESSAGE = "Bad passkey";
  public static final String VERIFICATION_UNAVAILABLE_MESSAGE =
      "Passkey verification is temporarily unavailable";

  private final IamAccountRepository accountRepo;
  private final IamPasskeyService passkeyService;
  private final ObjectMapper objectMapper = new ObjectMapper();

  public MultiFactorPasskeyCheckProvider(IamAccountRepository accountRepo,
      IamPasskeyService passkeyService) {
    this.accountRepo = accountRepo;
    this.passkeyService = passkeyService;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (!(authentication instanceof PasskeyAssertionAuthenticationToken token)) {
      return null;
    }

    Authentication preAuthentication = token.getPreAuthentication();

    if (!(preAuthentication instanceof ExtendedAuthenticationToken)
        && !(preAuthentication instanceof AbstractExternalAuthenticationToken)) {
      return null;
    }

    IamAccount account = accountRepo.findByUsername(preAuthentication.getName())
      .orElseThrow(() -> new BadCredentialsException("Invalid login details"));

    PasskeyAssertionDTO assertion = parseAssertion(token.getAssertion());

    // Only AuthenticationExceptions reach the failure handler: anything else would surface as an
    // error page, after the single-use challenge has already been consumed
    try {
      passkeyService.verifyPasskey(account, token.getChallenge(), assertion);
    } catch (PasskeyException e) {
      LOG.warn("Passkey verification failed for account '{}': {}", account.getUsername(),
          e.getMessage());
      throw new BadCredentialsException(BAD_PASSKEY_MESSAGE, e);
    } catch (DataAccessException e) {
      LOG.error("Passkey verification for account '{}' hit a database error",
          account.getUsername(), e);
      throw new AuthenticationServiceException(VERIFICATION_UNAVAILABLE_MESSAGE, e);
    } catch (RuntimeException e) {
      throw new InternalAuthenticationServiceException(VERIFICATION_UNAVAILABLE_MESSAGE, e);
    }

    return MultiFactorVerifiedTokenFactory.create(preAuthentication,
        new IamAuthenticationMethodReference(PASSKEY.getValue()));
  }

  private PasskeyAssertionDTO parseAssertion(String assertion) {
    if (assertion == null || assertion.isBlank()) {
      throw new BadCredentialsException(BAD_PASSKEY_MESSAGE);
    }
    try {
      PasskeyAssertionDTO dto = objectMapper.readValue(assertion, PasskeyAssertionDTO.class);
      if (dto.getId() == null || dto.getResponse() == null
          || dto.getResponse().getClientDataJSON() == null
          || dto.getResponse().getAuthenticatorData() == null
          || dto.getResponse().getSignature() == null) {
        throw new BadCredentialsException(BAD_PASSKEY_MESSAGE);
      }
      return dto;
    } catch (IOException e) {
      throw new BadCredentialsException(BAD_PASSKEY_MESSAGE, e);
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return PasskeyAssertionAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
