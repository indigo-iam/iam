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

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge.Purpose;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyDisabledException;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;

/**
 * The passkey service of an instance where the feature is switched off: no ceremony can run and
 * no stored passkey counts as an active second factor, but stored passkeys remain visible and
 * removable by their owner and by administrators
 */
public class DisabledIamPasskeyService extends AbstractIamPasskeyService {

  public static final String DISABLED_MESSAGE = "Passkeys are disabled on this IAM instance";

  public DisabledIamPasskeyService(IamPasskeyRepository passkeyRepository,
      IamAccountService accountService, NotificationFactory notificationFactory,
      ApplicationEventPublisher eventPublisher) {
    super(passkeyRepository, accountService, notificationFactory, eventPublisher);
  }

  @Override
  public boolean isEnabled() {
    return false;
  }

  @Override
  public boolean isPasskeyActive(IamAccount account) {
    return false;
  }

  @Override
  public PasskeyChallenge createChallenge(IamAccount account, Purpose purpose) {
    throw new PasskeyDisabledException(DISABLED_MESSAGE);
  }

  @Override
  public PasskeyRegistrationOptionsDTO getRegistrationOptions(IamAccount account,
      PasskeyChallenge challenge) {
    throw new PasskeyDisabledException(DISABLED_MESSAGE);
  }

  @Override
  public IamPasskey registerPasskey(IamAccount account, PasskeyChallenge challenge,
      PasskeyRegistrationDTO registration) {
    throw new PasskeyDisabledException(DISABLED_MESSAGE);
  }

  @Override
  public PasskeyAssertionOptionsDTO getAssertionOptions(IamAccount account,
      PasskeyChallenge challenge) {
    throw new PasskeyDisabledException(DISABLED_MESSAGE);
  }

  @Override
  public IamPasskey verifyPasskey(IamAccount account, PasskeyChallenge challenge,
      PasskeyAssertionDTO assertion) {
    throw new PasskeyDisabledException(DISABLED_MESSAGE);
  }

  /**
   * A stored passkey is not accepted at login while the feature is disabled, so removing it does
   * not weaken the account: no proof of a second factor is required
   */
  @Override
  @Transactional
  public IamPasskey removePasskey(IamAccount account, String passkeyUuid,
      PasskeyChallenge challenge, PasskeyRemovalDTO proof) {
    IamPasskey passkey = findPasskey(account, passkeyUuid);
    deletePasskey(account, passkey);
    return passkey;
  }
}
