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

import static it.infn.mw.iam.api.account.multi_factor_authentication.DefaultIamTotpMfaService.RECOVERY_CODE_QUANTITY;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Service;

import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.RecoveryCodesResetEvent;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@Service
public class DefaultIamTotpRecoveryCodeResetService
    implements IamTotpRecoveryCodeResetService, ApplicationEventPublisherAware {

  private final IamAccountRepository accountRepository;
  private final IamTotpMfaRepository totpMfaRepository;
  private final RecoveryCodeGenerator recoveryCodeGenerator;
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  public DefaultIamTotpRecoveryCodeResetService(IamAccountRepository accountRepository,
      IamTotpMfaRepository totpMfaRepository, RecoveryCodeGenerator recoveryCodeGenerator) {
    this.accountRepository = accountRepository;
    this.totpMfaRepository = totpMfaRepository;
    this.recoveryCodeGenerator = recoveryCodeGenerator;
  }

  @Override
  public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.eventPublisher = applicationEventPublisher;
  }

  /**
   * Regenerates the recovery codes attached to a provided MFA-enabled IAM account
   * 
   * @param account - the account to regenerate codes on
   */
  @Override
  public void resetRecoveryCodes(IamAccount account) {
    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account);
    if (!totpMfaOptional.isPresent()) {
      throw new MfaSecretNotFoundException("No multi-factor secret is attached to this account");
    }

    IamTotpMfa totpMfa = totpMfaOptional.get();
    String[] recoveryCodeStrings = recoveryCodeGenerator.generateCodes(RECOVERY_CODE_QUANTITY);
    Set<IamTotpRecoveryCode> recoveryCodes = new HashSet<>();
    for (String code : recoveryCodeStrings) {
      IamTotpRecoveryCode recoveryCode = new IamTotpRecoveryCode(totpMfa);
      recoveryCode.setCode(code);
      recoveryCodes.add(recoveryCode);
    }

    // Attach to account
    totpMfa.setRecoveryCodes(recoveryCodes);
    totpMfa.touch();
    account.touch();
    accountRepository.save(account);
    totpMfaRepository.save(totpMfa);
    eventPublisher.publishEvent(new RecoveryCodesResetEvent(this, account));
  }

}
