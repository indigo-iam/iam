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

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Service;

import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.AuthenticatorAppDisabledEvent;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.AuthenticatorAppEnabledEvent;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.exception.MfaSecretAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.core.user.exception.TotpMfaAlreadyEnabledException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@Service
public class DefaultIamTotpMfaService implements IamTotpMfaService, ApplicationEventPublisherAware {

  private final IamAccountService iamAccountService;
  private final IamTotpMfaRepository totpMfaRepository;
  private final SecretGenerator secretGenerator;
  private final RecoveryCodeGenerator recoveryCodeGenerator;
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  public DefaultIamTotpMfaService(IamAccountService iamAccountService,
      IamTotpMfaRepository totpMfaRepository, SecretGenerator secretGenerator,
      RecoveryCodeGenerator recoveryCodeGenerator, ApplicationEventPublisher eventPublisher) {
    this.iamAccountService = iamAccountService;
    this.totpMfaRepository = totpMfaRepository;
    this.secretGenerator = secretGenerator;
    this.recoveryCodeGenerator = recoveryCodeGenerator;
    this.eventPublisher = eventPublisher;
  }

  private void authenticatorAppEnabledEvent(IamAccount account) {
    eventPublisher.publishEvent(new AuthenticatorAppEnabledEvent(this, account));
  }

  private void authenticatorAppDisabledEvent(IamAccount account) {
    eventPublisher.publishEvent(new AuthenticatorAppDisabledEvent(this, account));
  }

  @Override
  public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.eventPublisher = applicationEventPublisher;
  }

  /**
   * Generates and attaches a TOTP MFA secret to a user account, along with a set of recovery codes
   * This is pre-emptive to actually enabling TOTP MFA on the account - the secret is written for
   * server-side TOTP verification
   * 
   * @param account the account to add the secret to
   * @return the new TOTP secret
   */
  @Override
  public IamTotpMfa addTotpMfaSecret(IamAccount account) {
    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account);
    if (totpMfaOptional.isPresent() && totpMfaOptional.get().isActive()) {
      throw new MfaSecretAlreadyBoundException(
          "A multi-factor secret is already assigned to this account");
    }

    // Generate secret
    IamTotpMfa totpMfa = new IamTotpMfa(account);
    totpMfa.setSecret(secretGenerator.generate());
    totpMfa.setAccount(account);

    Set<IamTotpRecoveryCode> recoveryCodes = generateRecoveryCodes(totpMfa);
    totpMfa.setRecoveryCodes(recoveryCodes);
    totpMfaRepository.save(totpMfa);
    return totpMfa;
  }

  /**
   * Adds a set of recovery codes to a given account's TOTP secret.
   * 
   * @param account the account to add recovery codes to
   * @return the affected TOTP secret
   */
  @Override
  public IamTotpMfa addTotpMfaRecoveryCodes(IamAccount account) {
    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account);
    if (!totpMfaOptional.isPresent()) {
      throw new MfaSecretNotFoundException("No multi-factor secret is attached to this account");
    }

    IamTotpMfa totpMfa = totpMfaOptional.get();

    Set<IamTotpRecoveryCode> recoveryCodes = generateRecoveryCodes(totpMfa);

    // Attach to account
    totpMfa.setRecoveryCodes(recoveryCodes);
    totpMfa.touch();
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
    authenticatorAppEnabledEvent(account);
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
    authenticatorAppDisabledEvent(account);
    return totpMfa;
  }

  private Set<IamTotpRecoveryCode> generateRecoveryCodes(IamTotpMfa totpMfa) {
    String[] recoveryCodeStrings = recoveryCodeGenerator.generateCodes(6);
    Set<IamTotpRecoveryCode> recoveryCodes = new HashSet<>();
    for (String code : recoveryCodeStrings) {
      IamTotpRecoveryCode recoveryCode = new IamTotpRecoveryCode(totpMfa);
      recoveryCode.setCode(code);
      recoveryCodes.add(recoveryCode);
    }
    return recoveryCodes;
  }
}
