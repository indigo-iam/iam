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
package it.infn.mw.iam.notification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.support.TransactionTemplate;

import it.infn.mw.iam.audit.events.account.AccountLoginSuspendedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
public class AccountLoginSuspendedNotificationListener {

  private static final Logger LOG =
      LoggerFactory.getLogger(AccountLoginSuspendedNotificationListener.class);

  private final IamAccountRepository accountRepo;
  private final NotificationFactory notificationFactory;
  private final IamProperties properties;
  private final TransactionTemplate notificationTransaction;

  public AccountLoginSuspendedNotificationListener(IamAccountRepository accountRepo,
      NotificationFactory notificationFactory, IamProperties properties,
      PlatformTransactionManager transactionManager) {

    this.accountRepo = accountRepo;
    this.notificationFactory = notificationFactory;
    this.properties = properties;

    notificationTransaction = new TransactionTemplate(transactionManager);
    notificationTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
  }

  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void onAccountLoginSuspended(AccountLoginSuspendedEvent event) {
    String accountUuid = event.getAccount().getUuid();

    try {
      notificationTransaction.executeWithoutResult(status -> accountRepo.findByUuid(accountUuid)
        .ifPresent(account -> notificationFactory.createAccountLockedMessage(account,
            properties.getLoginLockout().getLockDuration())));
    } catch (RuntimeException e) {
      LOG.error("Could not create lockout notification for account {}", accountUuid, e);
    }
  }
}
