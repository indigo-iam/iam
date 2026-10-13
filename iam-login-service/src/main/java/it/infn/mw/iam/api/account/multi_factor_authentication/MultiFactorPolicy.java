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
package it.infn.mw.iam.api.account.multi_factor_authentication;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.IamPasskeyService;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.config.mfa.IamPasskeyProperties;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

/**
 * Answers the questions the login flow asks about the second factor of an account, whichever the
 * factor is: the authenticator app, a passkey or both. The authentication providers, the
 * enforcement filter and the enrolment endpoints only rely on this class, so that the policy is
 * the same for local, OIDC, SAML and X.509 logins
 */
public class MultiFactorPolicy {

  public static final String MFA_ALREADY_ACTIVE_MESSAGE =
      "Multi-factor authentication is already active on this account: "
          + "verify your second factor before adding a new one";

  public static final String LAST_FACTOR_MESSAGE =
      "Multi-factor authentication is mandatory: register a passkey before disabling the "
          + "authenticator app";
  public static final String ONLY_FACTOR_MESSAGE =
      "Multi-factor authentication is mandatory and the authenticator app is the only second "
          + "factor available on this instance: it cannot be disabled";

  private final IamTotpMfaService totpMfaService;
  private final IamTotpMfaProperties totpMfaProperties;
  private final IamPasskeyService passkeyService;
  private final IamPasskeyProperties passkeyProperties;
  private final IamAccountRepository accountRepository;

  public MultiFactorPolicy(IamTotpMfaService totpMfaService,
      IamTotpMfaProperties totpMfaProperties, IamPasskeyService passkeyService,
      IamPasskeyProperties passkeyProperties, IamAccountRepository accountRepository) {
    this.totpMfaService = totpMfaService;
    this.totpMfaProperties = totpMfaProperties;
    this.passkeyService = passkeyService;
    this.passkeyProperties = passkeyProperties;
    this.accountRepository = accountRepository;
  }

  /**
   * @return true if every account must have a second factor
   */
  public boolean isMandatory() {
    return totpMfaProperties.isMultiFactorMandatory() || isPasskeyMandatory();
  }

  /**
   * @return true if every account must have a passkey
   */
  public boolean isPasskeyMandatory() {
    return passkeyService.isEnabled() && passkeyProperties.isMandatory();
  }

  /**
   * @param account
   * @return true if the account has at least one second factor to verify at login
   */
  public boolean isActive(IamAccount account) {
    return totpMfaService.isAuthenticatorAppActive(account)
        || passkeyService.isPasskeyActive(account);
  }

  /**
   * @param account
   * @return true if the account must be sent to the enrolment page: a second factor is mandatory
   *         and the account has none, or passkeys are mandatory and the account has no passkey
   */
  public boolean requiresEnrolment(IamAccount account) {
    // A registered passkey satisfies both policies, so one query answers the question
    if (isPasskeyMandatory()) {
      return !passkeyService.isPasskeyActive(account);
    }
    return isMandatory() && !isActive(account);
  }

  /**
   * @param account
   * @return true if passkeys are mandatory and the account has none yet
   */
  public boolean requiresPasskeyEnrolment(IamAccount account) {
    return isPasskeyMandatory() && !passkeyService.isPasskeyActive(account);
  }

  /**
   * @param account
   * @return true if the passkey is the only second factor accepted for the account, i.e. passkeys
   *         are mandatory and the account owns one
   */
  public boolean onlyPasskeyAccepted(IamAccount account) {
    return isPasskeyMandatory() && passkeyService.isPasskeyActive(account);
  }

  /**
   * A pre-authenticated user (first factor verified, second factor pending) may only enrol a
   * first factor: once a factor is active on the account, new factors can be added only after the
   * second factor has been verified. Otherwise a stolen password could be turned into a second
   * factor
   *
   * @param preAuthenticated whether the caller is pre-authenticated
   * @param account the account the factor would be added to
   * @throws AccessDeniedException if the enrolment is not allowed
   */
  public void checkEnrolmentAllowed(boolean preAuthenticated, IamAccount account) {
    if (preAuthenticated && isActive(account)) {
      throw new AccessDeniedException(MFA_ALREADY_ACTIVE_MESSAGE);
    }
  }

  /**
   * Disables the authenticator app of the account, unless a second factor is mandatory and no
   * passkey would be left. Under a mandatory policy the account row is locked for the whole
   * operation, so that a concurrent passkey removal, which takes the same lock, cannot leave the
   * account without any factor
   *
   * @param account the account whose authenticator app is disabled
   * @return the disabled authenticator app settings
   * @throws MandatoryFactorException if the authenticator app is the last mandatory factor
   */
  @Transactional
  public IamTotpMfa disableAuthenticatorApp(IamAccount account) {
    if (isMandatory()) {
      accountRepository.findByIdForUpdate(account.getId())
        .orElseThrow(() -> NoSuchAccountError.forUsername(account.getUsername()));
      if (!passkeyService.isPasskeyActive(account)) {
        throw new MandatoryFactorException(
            passkeyService.isEnabled() ? LAST_FACTOR_MESSAGE : ONLY_FACTOR_MESSAGE);
      }
    }
    return totpMfaService.disableTotpMfa(account);
  }
}
