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
package it.infn.mw.iam.api.account.multi_factor_authentication.passkey;

import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.REQUESTING_MFA;
import static it.infn.mw.iam.api.utils.ValidationErrorUtils.stringifyValidationError;

import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorPolicy;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge.Purpose;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyCeremonyException;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyDisabledException;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyLimitExceededException;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyNotFoundException;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

/**
 * Controller for managing the passkeys of a user account. Registration is a two step WebAuthn
 * ceremony: the options endpoint issues a challenge that is kept in the session, the registration
 * endpoint receives the credential created by the browser. The authentication options endpoint
 * issues the challenge for the step-up verification at /iam/verify
 */
@SuppressWarnings("deprecation")
@Controller
public class PasskeyController {

  public static final String BASE_URL = "/iam/passkey";
  public static final String REGISTRATION_OPTIONS_URL = BASE_URL + "/registration/options";
  public static final String REGISTRATION_URL = BASE_URL + "/registration";
  public static final String AUTHENTICATION_OPTIONS_URL = BASE_URL + "/authentication/options";
  public static final String PASSKEY_URL = BASE_URL + "/{passkeyId}";
  public static final String RESET_URL_FOR_ACCOUNT_ID = BASE_URL + "/reset/{accountId}";

  public static final String INVALID_REGISTRATION_TEMPLATE = "Invalid passkey registration: %s";

  private final IamPasskeyService service;
  private final IamAccountRepository accountRepository;
  private final AccountUtils accountUtils;
  private final MultiFactorPolicy multiFactorPolicy;

  public PasskeyController(IamPasskeyService service, IamAccountRepository accountRepository,
      AccountUtils accountUtils, MultiFactorPolicy multiFactorPolicy) {
    this.service = service;
    this.accountRepository = accountRepository;
    this.accountUtils = accountUtils;
    this.multiFactorPolicy = multiFactorPolicy;
  }

  /**
   * Lists the passkeys registered on the logged-in user account
   *
   * @return the list of passkeys
   */
  @PreAuthorize("hasRole('USER')")
  @GetMapping(value = BASE_URL, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public List<PasskeyDTO> getPasskeys() {
    IamAccount account = getAuthenticatedAccount();
    return service.getPasskeys(account).stream().map(PasskeyDTO::from).collect(Collectors.toList());
  }

  /**
   * Issues a registration challenge and returns the options for navigator.credentials.create().
   * Also reachable by pre-authenticated users enrolling their first factor at /iam/mfa/activate
   *
   * @param session the user session the challenge is bound to
   * @return the creation options
   */
  @PreAuthorize("hasAnyRole('USER', 'PRE_AUTHENTICATED')")
  @PostMapping(value = REGISTRATION_OPTIONS_URL, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public PasskeyRegistrationOptionsDTO getRegistrationOptions(HttpSession session) {
    IamAccount account = getAuthenticatedAccount();
    checkEnrolmentAllowed(account);
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);
    session.setAttribute(PasskeyChallenge.SESSION_ATTRIBUTE, challenge);
    return service.getRegistrationOptions(account, challenge);
  }

  /**
   * Completes the registration of a new passkey
   *
   * @param registration the credential created by the browser and the chosen label
   * @param validationResult result of validation checks on the request
   * @param session the user session holding the challenge
   * @return the new passkey
   */
  @PreAuthorize("hasAnyRole('USER', 'PRE_AUTHENTICATED')")
  @PostMapping(value = REGISTRATION_URL, consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.CREATED)
  @ResponseBody
  public PasskeyDTO registerPasskey(@RequestBody @Valid PasskeyRegistrationDTO registration,
      BindingResult validationResult, HttpSession session) {

    IamAccount account = getAuthenticatedAccount();
    checkEnrolmentAllowed(account);

    if (validationResult.hasErrors()) {
      throw new PasskeyCeremonyException(String.format(INVALID_REGISTRATION_TEMPLATE,
          stringifyValidationError(validationResult)));
    }

    PasskeyChallenge challenge = consumeChallenge(session);
    IamPasskey passkey = service.registerPasskey(account, challenge, registration);
    session.removeAttribute(REQUESTING_MFA);
    return PasskeyDTO.from(passkey);
  }

  /**
   * Issues an authentication challenge and returns the options for navigator.credentials.get()
   * used in the step-up verification flow
   *
   * @param session the user session the challenge is bound to
   * @return the request options
   */
  @PreAuthorize("hasRole('PRE_AUTHENTICATED')")
  @PostMapping(value = AUTHENTICATION_OPTIONS_URL, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public PasskeyAssertionOptionsDTO getAuthenticationOptions(HttpSession session) {
    IamAccount account = getAuthenticatedAccount();
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.AUTHENTICATION);
    session.setAttribute(PasskeyChallenge.SESSION_ATTRIBUTE, challenge);
    return service.getAuthenticationOptions(account, challenge);
  }

  /**
   * Removes one passkey from the logged-in user account
   *
   * @param passkeyId the passkey identifier
   */
  @PreAuthorize("hasRole('USER')")
  @DeleteMapping(value = PASSKEY_URL)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @ResponseBody
  public void removePasskey(@PathVariable String passkeyId) {
    IamAccount account = getAuthenticatedAccount();
    service.removePasskey(account, passkeyId);
  }

  /**
   * Removes every passkey from an account, on request of an administrator
   *
   * @param accountId the account uuid
   */
  @PreAuthorize("hasRole('ADMIN')")
  @DeleteMapping(value = RESET_URL_FOR_ACCOUNT_ID)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @ResponseBody
  public void resetPasskeysForAccount(@PathVariable String accountId) {
    IamAccount account = accountRepository.findByUuid(accountId)
      .orElseThrow(() -> NoSuchAccountError.forUuid(accountId));
    service.removeAllPasskeys(account);
  }

  private void checkEnrolmentAllowed(IamAccount account) {
    multiFactorPolicy.checkEnrolmentAllowed(accountUtils.isPreAuthenticated(), account);
  }

  /**
   * A challenge is single use: it leaves the session before the ceremony is verified, so that a
   * failed attempt must start again with a fresh one
   */
  private PasskeyChallenge consumeChallenge(HttpSession session) {
    Object challenge = session.getAttribute(PasskeyChallenge.SESSION_ATTRIBUTE);
    session.removeAttribute(PasskeyChallenge.SESSION_ATTRIBUTE);
    return challenge instanceof PasskeyChallenge passkeyChallenge ? passkeyChallenge : null;
  }

  private IamAccount getAuthenticatedAccount() {
    final String username = getUsernameFromSecurityContext();
    return accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));
  }

  private String getUsernameFromSecurityContext() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof OAuth2Authentication oauth) {
      auth = oauth.getUserAuthentication();
    }
    return auth.getName();
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(PasskeyCeremonyException.class)
  @ResponseBody
  public ErrorDTO handlePasskeyCeremonyException(PasskeyCeremonyException e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(PasskeyDisabledException.class)
  @ResponseBody
  public ErrorDTO handlePasskeyDisabledException(PasskeyDisabledException e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.CONFLICT)
  @ExceptionHandler(PasskeyLimitExceededException.class)
  @ResponseBody
  public ErrorDTO handlePasskeyLimitExceededException(PasskeyLimitExceededException e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.NOT_FOUND)
  @ExceptionHandler(PasskeyNotFoundException.class)
  @ResponseBody
  public ErrorDTO handlePasskeyNotFoundException(PasskeyNotFoundException e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.NOT_FOUND)
  @ExceptionHandler(NoSuchAccountError.class)
  @ResponseBody
  public ErrorDTO handleNoSuchAccountError(NoSuchAccountError e) {
    return ErrorDTO.fromString(e.getMessage());
  }
}
