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
package it.infn.mw.iam.test.login;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.time.Clock;
import java.time.Duration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.audit.events.account.AccountLoginSuspendedEvent;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.config.ClockConfig;

@SpringBootTest(classes = {IamLoginService.class, ClockConfig.class},
    webEnvironment = WebEnvironment.NONE,
    properties = {"iam.login-lockout.enabled=true", "iam.login-lockout.max-failed-attempts=1",
        "iam.login-lockout.observation-window=15m", "iam.login-lockout.lock-duration=30m"})
@Execution(ExecutionMode.SAME_THREAD)
class LoginLockoutNotificationIntegrationTests {

  private static final Duration LOCK_DURATION = Duration.ofMinutes(30);

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAccountLoginLockoutRepository lockoutRepo;

  @Autowired
  private PlatformTransactionManager transactionManager;

  @Autowired
  private ApplicationContext applicationContext;

  @Autowired
  private Clock clock;

  @MockBean
  private NotificationFactory notifications;

  private TransactionTemplate tx;
  private String accountUuid;

  @BeforeEach
  void setUp() {
    tx = new TransactionTemplate(transactionManager);

    accountUuid = tx.execute(status -> {
      IamAccount account = accountRepo.findByUsername("test")
        .orElseThrow(() -> new AssertionError("Missing test account"));

      assertTrue(account.isActive());
      return account.getUuid();
    });

    removeLockout();
  }

  @AfterEach
  void cleanUp() {
    if (tx != null && accountUuid != null) {
      removeLockout();
    }
  }

  @Test
  void committedSuspensionTriggersNotification() {
    doAnswer(invocation -> {
      IamAccount account = invocation.getArgument(0);

      assertEquals(accountUuid, account.getUuid());
      assertTrue(TransactionSynchronizationManager.isActualTransactionActive(),
          "Notification creation must execute inside a transaction");

      return null;
    }).when(notifications).createAccountLockedMessage(any(IamAccount.class), eq(LOCK_DURATION));

    accountService.loginFailedAttempt(accountUuid);

    verify(notifications).createAccountLockedMessage(any(IamAccount.class), eq(LOCK_DURATION));

    assertPersistedSuspension();
  }

  @Test
  void notificationIsDeferredUntilPublishingTransactionCommits() {
    tx.executeWithoutResult(status -> {
      publishSuspensionEvent();

      // The publishing transaction has not committed yet.
      verifyNoInteractions(notifications);
    });

    verify(notifications).createAccountLockedMessage(any(IamAccount.class), eq(LOCK_DURATION));
  }

  @Test
  void rolledBackPublishingTransactionDoesNotTriggerNotification() {
    tx.executeWithoutResult(status -> {
      publishSuspensionEvent();

      verifyNoInteractions(notifications);
      status.setRollbackOnly();
    });

    verifyNoInteractions(notifications);
  }

  @Test
  void notificationFailureDoesNotRollBackSuspensionOrEscapeToCaller() {
    doThrow(new IllegalStateException("Simulated notification failure")).when(notifications)
      .createAccountLockedMessage(any(IamAccount.class), eq(LOCK_DURATION));

    assertDoesNotThrow(() -> accountService.loginFailedAttempt(accountUuid));

    verify(notifications).createAccountLockedMessage(any(IamAccount.class), eq(LOCK_DURATION));

    // Read again after the service and listener have completed.
    assertPersistedSuspension();
  }

  private void publishSuspensionEvent() {
    IamAccount account = accountRepo.findByUuid(accountUuid)
      .orElseThrow(() -> new AssertionError("Missing test account"));

    applicationContext.publishEvent(new AccountLoginSuspendedEvent(this, account));
  }

  private void assertPersistedSuspension() {
    tx.executeWithoutResult(status -> {
      var lockout = lockoutRepo.findByAccountUuid(accountUuid)
        .orElseThrow(() -> new AssertionError("Missing lockout record"));

      assertEquals(1, lockout.getFailedAttempts());
      assertEquals(1, lockout.getLockoutCount());
      assertTrue(lockout.isSuspended(clock.instant()));
    });
  }

  private void removeLockout() {
    tx.executeWithoutResult(
        status -> lockoutRepo.findByAccountUuid(accountUuid).ifPresent(lockoutRepo::delete));
  }
}
