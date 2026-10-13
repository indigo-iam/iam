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

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyNotFoundException;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.PasskeyRemovedEvent;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;

/**
 * The part of the passkey service that does not depend on the feature being enabled: stored
 * passkeys can always be listed and removed, with the same audit trail and notifications, so that
 * credentials registered before the feature was switched off neither hide nor survive a reset
 */
public abstract class AbstractIamPasskeyService implements IamPasskeyService {

  private static final Logger LOG = LoggerFactory.getLogger(AbstractIamPasskeyService.class);

  public static final String PASSKEY_NOT_FOUND_MESSAGE = "Passkey not found";

  protected final IamPasskeyRepository passkeyRepository;
  protected final NotificationFactory notificationFactory;
  protected final ApplicationEventPublisher eventPublisher;
  private final IamAccountService accountService;

  protected AbstractIamPasskeyService(IamPasskeyRepository passkeyRepository,
      IamAccountService accountService, NotificationFactory notificationFactory,
      ApplicationEventPublisher eventPublisher) {
    this.passkeyRepository = passkeyRepository;
    this.accountService = accountService;
    this.notificationFactory = notificationFactory;
    this.eventPublisher = eventPublisher;
  }

  @Override
  @Transactional(readOnly = true)
  public List<IamPasskey> getPasskeys(IamAccount account) {
    return passkeyRepository.findByAccountId(account.getId());
  }

  @Override
  @Transactional
  public List<IamPasskey> removeAllPasskeys(IamAccount account) {

    List<IamPasskey> passkeys = passkeyRepository.findByAccountId(account.getId());

    if (passkeys.isEmpty()) {
      return passkeys;
    }

    passkeyRepository.deleteAll(passkeys);
    accountService.saveAccount(account);
    passkeys.forEach(p -> eventPublisher.publishEvent(new PasskeyRemovedEvent(this, account, p)));
    notificationFactory.createPasskeysResetMessage(account);

    LOG.info("All passkeys ({}) removed from account '{}'", passkeys.size(),
        account.getUsername());
    return passkeys;
  }

  protected void saveAccount(IamAccount account) {
    accountService.saveAccount(account);
  }

  protected IamPasskey findPasskey(IamAccount account, String passkeyUuid) {
    return passkeyRepository.findByUuidAndAccountId(passkeyUuid, account.getId())
      .orElseThrow(() -> new PasskeyNotFoundException(PASSKEY_NOT_FOUND_MESSAGE));
  }

  protected void deletePasskey(IamAccount account, IamPasskey passkey) {
    passkeyRepository.delete(passkey);
    accountService.saveAccount(account);
    eventPublisher.publishEvent(new PasskeyRemovedEvent(this, account, passkey));
    notificationFactory.createPasskeyRemovedMessage(account, passkey);

    LOG.info("Passkey '{}' removed from account '{}'", passkey.getLabel(), account.getUsername());
  }
}
