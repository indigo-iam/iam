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

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Service;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.secret.SecretGenerator;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.AuthenticatorAppDisabledEvent;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.AuthenticatorAppEnabledEvent;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.TotpVerifiedEvent;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.exception.MfaSecretAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.core.user.exception.TotpMfaAlreadyEnabledException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;

@Service
public class DefaultIamTotpMfaService implements IamTotpMfaService, ApplicationEventPublisherAware {

  public static final int RECOVERY_CODE_QUANTITY = 6;

  private final IamAccountService iamAccountService;
  private final IamTotpMfaRepository totpMfaRepository;
  private final SecretGenerator secretGenerator;
  private final CodeVerifier codeVerifier;
  private final IamTotpMfaProperties iamTotpMfaProperties;
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  public DefaultIamTotpMfaService(IamAccountService iamAccountService,
      IamTotpMfaRepository totpMfaRepository, SecretGenerator secretGenerator,
      CodeVerifier codeVerifier, ApplicationEventPublisher eventPublisher,
      IamTotpMfaProperties iamTotpMfaProperties) {
    this.iamAccountService = iamAccountService;
    this.totpMfaRepository = totpMfaRepository;
    this.secretGenerator = secretGenerator;
    this.codeVerifier = codeVerifier;
    this.eventPublisher = eventPublisher;
    this.iamTotpMfaProperties = iamTotpMfaProperties;
  }

  private void authenticatorAppEnabledEvent(IamAccount account, IamTotpMfa totpMfa) {
    eventPublisher.publishEvent(new AuthenticatorAppEnabledEvent(this, account, totpMfa));
  }

  private void authenticatorAppDisabledEvent(IamAccount account, IamTotpMfa totpMfa) {
    eventPublisher.publishEvent(new AuthenticatorAppDisabledEvent(this, account, totpMfa));
  }

  private void totpVerifiedEvent(IamAccount account, IamTotpMfa totpMfa) {
    eventPublisher.publishEvent(new TotpVerifiedEvent(this, account, totpMfa));
  }

  @Override
  public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.eventPublisher = applicationEventPublisher;
  }

  /**
   * Generates and attaches a TOTP MFA secret to a user account
   * This is pre-emptive to actually enabling TOTP MFA on the account - the secret is written for
   * server-side TOTP verification during the user's enabling of MFA on their account
   * 
   * @param account the account to add the secret to
   * @return the new TOTP secret
   */
  @Override
  public IamTotpMfa addTotpMfaSecret(IamAccount account) throws IamTotpMfaInvalidArgumentError {
    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account);
    if (totpMfaOptional.isPresent()) {
      if (totpMfaOptional.get().isActive()) {
        throw new MfaSecretAlreadyBoundException(
            "A multi-factor secret is already assigned to this account");
      }

      totpMfaRepository.delete(totpMfaOptional.get());
    }

    // Generate secret
    IamTotpMfa totpMfa = new IamTotpMfa(account);

    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(
        secretGenerator.generate(), iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()));
    totpMfa.setAccount(account);

    totpMfaRepository.save(totpMfa);

    return totpMfa;
  }

  /**
   * Enables TOTP MFA on a provided account. Relies on the account already having a non-active TOTP
   * secret attached to it
   * 
   * @param account the account to enable TOTP MFA on
   * @return the newly-enabled TOTP secret
   */
  @Override
  public IamTotpMfa enableTotpMfa(IamAccount account) {
    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account);
    if (!totpMfaOptional.isPresent()) {
      throw new MfaSecretNotFoundException("No multi-factor secret is attached to this account");
    }

    IamTotpMfa totpMfa = totpMfaOptional.get();
    if (totpMfa.isActive()) {
      throw new TotpMfaAlreadyEnabledException("TOTP MFA is already enabled on this account");
    }

    totpMfa.setActive(true);
    totpMfa.touch();
    totpMfaRepository.save(totpMfa);
    iamAccountService.saveAccount(account);
    authenticatorAppEnabledEvent(account, totpMfa);
    return totpMfa;
  }

  /**
   * Disables TOTP MFA on a provided account. Relies on the account having an active TOTP secret
   * attached to it. Disabling means to delete the secret entirely (if a user chooses to enable
   * again, a new secret is generated anyway)
   * 
   * @param account the account to disable TOTP MFA on
   * @return the newly-disabled TOTP MFA
   */
  @Override
  public IamTotpMfa disableTotpMfa(IamAccount account) {
    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account);
    if (!totpMfaOptional.isPresent()) {
      throw new MfaSecretNotFoundException("No multi-factor secret is attached to this account");
    }

    IamTotpMfa totpMfa = totpMfaOptional.get();
    totpMfaRepository.delete(totpMfa);

    iamAccountService.saveAccount(account);
    authenticatorAppDisabledEvent(account, totpMfa);
    return totpMfa;
  }

  /**
   * Verifies a provided TOTP against an account multi-factor secret
   * 
   * @param account the account whose secret we will check against
   * @param totp the TOTP to validate
   * @return true if valid, false otherwise
   */
  @Override
  public boolean verifyTotp(IamAccount account, String totp) throws IamTotpMfaInvalidArgumentError {
    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account);
    if (!totpMfaOptional.isPresent()) {
      throw new MfaSecretNotFoundException("No multi-factor secret is attached to this account");
    }

    IamTotpMfa totpMfa = totpMfaOptional.get();
    String mfaSecret = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecret(
        totpMfa.getSecret(), iamTotpMfaProperties.getPasswordToEncryptOrDecrypt());

    // Verify provided TOTP
    if (codeVerifier.isValidCode(mfaSecret, totp)) {
      totpVerifiedEvent(account, totpMfa);
      return true;
    }

    return false;
  }

}
