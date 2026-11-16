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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.sql.DataSource;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.lifecycle.cern.CernAccountLifecycleTask;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler;
import it.infn.mw.iam.test.lifecycle.cern.CernAccountLifecycleShedLockTests.Config.HrHandlerMockHolder;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.core.SimpleLock;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;

/** Exercises the real ShedLock proxy with a shared JDBC lock table. */
@SpringJUnitConfig(CernAccountLifecycleShedLockTests.Config.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class CernAccountLifecycleShedLockTests {

  @Configuration
  @EnableAspectJAutoProxy(proxyTargetClass = true)
  @EnableSchedulerLock(defaultLockAtMostFor = "PT2H", proxyTargetClass = true)
  static class Config {

    @Bean
    DataSource dataSource() {
      return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2).build();
    }

    @Bean
    JdbcTemplate jdbcTemplate(DataSource dataSource) {
      return new JdbcTemplate(dataSource);
    }

    @Bean
    LockProvider lockProvider(JdbcTemplate jdbcTemplate) {
      jdbcTemplate.execute("CREATE TABLE shedlock (name VARCHAR(64) NOT NULL PRIMARY KEY, "
          + "lock_until TIMESTAMP NOT NULL, locked_at TIMESTAMP NOT NULL, "
          + "locked_by VARCHAR(255) NOT NULL)");
      return new JdbcTemplateLockProvider(
          JdbcTemplateLockProvider.Configuration.builder().withJdbcTemplate(jdbcTemplate).build());
    }

    @Bean
    CernAccountLifecycleTask lifecycleTask(HrHandlerMockHolder holder,
        ExpiredAccountsHandler expiredAccountsHandler) {

      CernProperties cern = new CernProperties();
      cern.getTask().setEnabled(true);

      return new CernAccountLifecycleTask(cern, new LifecycleProperties(), holder.mock,
          expiredAccountsHandler);
    }

    @Bean
    ExpiredAccountsHandler expiredAccountsHandler() {
      return mock(ExpiredAccountsHandler.class);
    }

    static class HrHandlerMockHolder {
      final CernHrLifecycleHandler mock = mock(CernHrLifecycleHandler.class);
    }

    @Bean
    HrHandlerMockHolder hrHandlerMockHolder() {
      return new HrHandlerMockHolder();
    }
  }

  @Autowired
  CernAccountLifecycleTask task;

  @Autowired
  ExpiredAccountsHandler expired;

  @Autowired
  JdbcTemplate jdbc;

  @Autowired
  HrHandlerMockHolder holder;

  @Autowired
  LockProvider lockProvider;

  @BeforeEach
  void resetState() {
    reset(holder.mock, expired);
  }

  @Test
  void concurrentInvocationsDoNotQueueOrRunTwice() throws Exception {

    assertTrue(task.isEnabled(), "CERN lifecycle task must be enabled");
    assertTrue(AopUtils.isAopProxy(task), "CernAccountLifecycleTask must be proxied by Spring");

    assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM shedlock", Integer.class));

    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    AtomicInteger calls = new AtomicInteger();
    when(holder.mock.synchronizeAccounts()).thenAnswer(invocation -> {
      calls.incrementAndGet();
      entered.countDown();
      if (!release.await(5, TimeUnit.SECONDS)) {
        throw new IllegalStateException("Timed out waiting for test release");
      }
      return Set.of();
    });

    CompletableFuture<Void> first = CompletableFuture.runAsync(task::run);
    try {
      if (!entered.await(5, TimeUnit.SECONDS)) {
        first.get(1, TimeUnit.SECONDS);
        fail("First invocation completed without entering HR synchronization");
      }
      // The second invocation must return while the first still holds the lock.
      CompletableFuture<Void> second = CompletableFuture.runAsync(task::run);
      second.get(5, TimeUnit.SECONDS);
      assertEquals(1, calls.get());
    } finally {
      release.countDown();
      first.get(5, TimeUnit.SECONDS);
    }
    verify(expired).handleExpiredAccounts(Set.of());
  }

  @Test
  void exceptionReleasesLockForNextInvocation() {
    AtomicInteger calls = new AtomicInteger();
    when(holder.mock.synchronizeAccounts()).thenAnswer(invocation -> {
      if (calls.incrementAndGet() == 1) {
        throw new IllegalStateException("Simulated HR failure");
      }
      return Set.of();
    });

    assertThrows(IllegalStateException.class, task::run);
    task.run();

    assertEquals(2, calls.get());
    verify(expired).handleExpiredAccounts(Set.of());
  }

  @Test
  void lockProviderCanAcquireLock() {
    LockConfiguration configuration = new LockConfiguration(Instant.now(), "accountLifecycle",
        Duration.ofMinutes(5), Duration.ZERO);

    Optional<SimpleLock> lock = lockProvider.lock(configuration);

    assertTrue(lock.isPresent(), "Failed to acquire accountLifecycle lock");

    lock.get().unlock();
  }
}
