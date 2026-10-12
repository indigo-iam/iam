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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.NONE,
    properties = {
        "iam.login-lockout.enabled=true",
        "iam.login-lockout.max-failed-attempts=100",
        "iam.login-lockout.observation-window=15m",
        "iam.login-lockout.lock-duration=30m"
    })
@Execution(ExecutionMode.SAME_THREAD)
class LoginLockoutConcurrencyTests {

  private static final String TEST_UUID = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";
  private static final String USERNAME = "test";
  private static final int WORKERS = 8;

  @Autowired
  private IamAccountService service;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAccountLoginLockoutRepository lockoutRepo;

  @Autowired
  private PlatformTransactionManager transactionManager;

  private TransactionTemplate tx;
  private String accountUuid;

  @BeforeEach
  void prepareCommittedFixture() {
    tx = new TransactionTemplate(transactionManager);
    accountUuid = tx.execute(status -> {
      IamAccount account = accountRepo.findByUsername(USERNAME)
          .orElseThrow(() -> new AssertionError("Missing test account"));
      assertTrue(account.isActive(), "The test account must be active");
      return account.getUuid();
    });
    removeLockout();
  }

  @AfterEach
  void cleanupCommittedState() {
    if (tx != null && accountUuid != null) {
      removeLockout();
    }
  }

  @RepeatedTest(10)
  void concurrentFirstFailuresCreateOneRecordAndCountEveryAttempt() throws Exception {
    runConcurrentFailures();
    assertPersistedAttempts(WORKERS);
  }

  @RepeatedTest(10)
  void concurrentFailuresDoNotLoseUpdatesToAnExistingCounter() throws Exception {

    service.loginFailedAttempt(TEST_UUID);
    assertPersistedAttempts(1);
    runConcurrentFailures();
    assertPersistedAttempts(1 + WORKERS);
  }

  private void runConcurrentFailures() throws Exception {

    ExecutorService executor = Executors.newFixedThreadPool(WORKERS);
    CountDownLatch ready = new CountDownLatch(WORKERS);
    CountDownLatch start = new CountDownLatch(1);
    List<Future<?>> futures = new ArrayList<>();

    try {
      for (int i = 0; i < WORKERS; i++) {
        futures.add(executor.submit(() -> {
          ready.countDown();
          if (!start.await(10, TimeUnit.SECONDS)) {
            throw new AssertionError("Timed out waiting for the start gate");
          }
          service.loginFailedAttempt(accountUuid);
          return null;
        }));
      }

      assertTrue(ready.await(10, TimeUnit.SECONDS), "Workers did not reach the gate");
      start.countDown();

      List<Throwable> failures = new ArrayList<>();
      for (Future<?> future : futures) {
        try {
          future.get(30, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
          failures.add(e.getCause());
        }
      }
      if (!failures.isEmpty()) {
        AssertionError error = new AssertionError(
            "Concurrent failed-login recording produced " + failures.size() + " errors");
        failures.forEach(error::addSuppressed);
        throw error;
      }
    } finally {
      start.countDown();
      executor.shutdownNow();
      assertTrue(executor.awaitTermination(30, TimeUnit.SECONDS),
          "Worker threads did not stop; inspect database locks");
    }
  }

  private void assertPersistedAttempts(int expected) {

    tx.executeWithoutResult(status -> {
      IamAccountLoginLockout lockout = lockoutRepo.findByAccountUuid(accountUuid)
          .orElseThrow(() -> new AssertionError("Missing lockout record"));
      assertEquals(expected, lockout.getFailedAttempts(),
          "Every failed login must increment the persisted counter exactly once");
      assertEquals(0, lockout.getLockoutCount(),
          "The threshold must remain above all attempts made by this test");
    });
  }

  private void removeLockout() {

    tx.executeWithoutResult(status ->
        lockoutRepo.findByAccountUuid(accountUuid).ifPresent(lockoutRepo::delete));
  }
}
