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
import it.infn.mw.iam.authn.lockout.LoginLockoutService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;

/**
 * Database-backed regression tests for PR #1194.
 *
 * Place in iam-login-service/src/test/java/it/infn/mw/iam/test/authn/lockout/.
 * Uses the existing active "test" account fixture, as repository tests do.
 * Run only against a disposable test database, preferably MySQL/InnoDB.
 * Do not add @Transactional to this class: setup must commit before workers
 * start, and every worker must enter the proxied service in its own transaction.
 * Do not mock the repositories or instantiate the service with new.
 *
 * The start gate encourages overlapping requests without placing a barrier
 * inside a locked transaction (which would deadlock the corrected service).
 * Repetition improves race detection, but an unfixed implementation can still
 * pass if the scheduler happens to serialize all calls. This is not a
 * deterministic proof of the absence of races.
 *
 * From the repository root, with the usual test database configuration:
 * ./mvnw -pl iam-login-service -am
 *   -Dtest=LoginLockoutConcurrencyTests -Dsurefire.failIfNoSpecifiedTests=false test
 *
 * Prepared against PR head a82d7fce; not compiled or executed by the author
 * of this test artifact.
 */
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.NONE,
    properties = {
        "iam.login-lockout.enabled=true",
        "iam.login-lockout.max-failed-attempts-before-suspension=100",
        "iam.login-lockout.suspension-duration-minutes=30",
        "iam.login-lockout.disable-after-max-suspension-rounds=false"
    })
@Execution(ExecutionMode.SAME_THREAD)
class LoginLockoutConcurrencyTests {

  private static final String USERNAME = "test";
  private static final int WORKERS = 8;

  @Autowired
  private LoginLockoutService service;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAccountLoginLockoutRepository lockoutRepo;

  @Autowired
  private PlatformTransactionManager transactionManager;

  private TransactionTemplate tx;
  private Long accountId;

  @BeforeEach
  void prepareCommittedFixture() {
    tx = new TransactionTemplate(transactionManager);
    accountId = tx.execute(status -> {
      IamAccount account = accountRepo.findByUsername(USERNAME)
          .orElseThrow(() -> new AssertionError("Missing test account fixture"));
      assertTrue(account.isActive(), "The fixture account must be active");
      return account.getId();
    });
    removeLockout();
  }

  @AfterEach
  void cleanupCommittedState() {
    if (tx != null && accountId != null) {
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
    // Commit the seed through the actual proxied service.
    service.recordFailedAttempt(USERNAME);
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
          // No surrounding test transaction: Spring starts and commits one
          // transaction per call on the worker thread.
          service.recordFailedAttempt(USERNAME);
          return null;
        }));
      }

      assertTrue(ready.await(10, TimeUnit.SECONDS), "Workers did not reach the gate");
      start.countDown();

      // Inspect every worker; never hide a duplicate-key/deadlock exception.
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
    // Read after every worker has committed, in a fresh persistence context.
    tx.executeWithoutResult(status -> {
      IamAccountLoginLockout lockout = lockoutRepo.findByAccountId(accountId)
          .orElseThrow(() -> new AssertionError("Missing lockout record"));
      assertEquals(expected, lockout.getFailedAttempts(),
          "Every failed login must increment the persisted counter exactly once");
      assertEquals(0, lockout.getLockoutCount(),
          "The threshold must remain above all attempts made by this test");
    });
  }

  private void removeLockout() {
    tx.executeWithoutResult(status ->
        lockoutRepo.findByAccountId(accountId).ifPresent(lockoutRepo::delete));
  }
}
