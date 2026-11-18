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
package it.infn.mw.iam.test.lifecycle.cern;

import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.LIFECYCLE_STATUS_LABEL;
import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.AccountLifecycleStatus.SUSPENDED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleAccountProcessor;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.clock.MutableClock;

/** Regression test: a rolled-back HR synchronization must not emit a restoration notification. */
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class})
@TestPropertySource(properties = {"spring.profiles.include=${spring.profiles.active:h2-test},cern"})
class CernHrLifecycleNotificationRollbackTests implements LifecycleTestSupport {

  @Autowired
  IamAccountService accountService;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  CernHrLifecycleAccountProcessor processor;

  @Autowired
  PlatformTransactionManager transactionManager;

  @Autowired
  MutableClock clock;

  @MockBean
  NotificationFactory notificationFactory;

  @Autowired
  IamEmailNotificationRepository notificationRepo;

  @Test
  void rollbackAfterRestorationDoesNotEmitNotification() {
    String uuid = UUID.randomUUID().toString();
    IamAccount account = IamAccount.newAccount();
    account.setUuid(uuid);
    account.setUsername("cern-rollback-" + uuid);
    account.setActive(true);
    account.setEndTime(Date.from(clock.daysAfter(365)));
    account.getUserInfo().setEmail("cern-rollback-" + uuid + "@example.org");
    account.getUserInfo().setGivenName("Cern");
    account.getUserInfo().setFamilyName("Rollback");
    account.getUserInfo().setEmailVerified(true);
    accountService.createAccount(account);

    long notificationsBefore = notificationRepo.count();

    try {
      accountService.disableAccount(account);
      accountService.addLabel(account,
          IamLabel.builder().name(LIFECYCLE_STATUS_LABEL).value(SUSPENDED.name()).build());

      VOPersonDTO person = voPerson(clock, CERN_PERSON_ID);
      TransactionTemplate tx = new TransactionTemplate(transactionManager);
      assertThrows(IllegalStateException.class, () -> tx.execute(status -> {
        processor.process(uuid, CERN_PERSON_ID, "test", Optional.of(person));
        throw new IllegalStateException("Force rollback after account restoration");
      }));

      assertFalse(accountRepo.findByUuid(uuid).orElseThrow().isActive(),
          "Account restoration must be rolled back");
      assertEquals(notificationsBefore, notificationRepo.count());
    } finally {
      accountService.deleteAccount(accountRepo.findByUuid(uuid).orElseThrow());
    }
  }
}
