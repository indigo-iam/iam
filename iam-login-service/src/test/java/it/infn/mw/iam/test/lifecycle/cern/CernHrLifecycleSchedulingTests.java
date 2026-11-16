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
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;

import java.util.Optional;

import org.mockito.InOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.data.domain.Page;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.lifecycle.cern.CernAccountLifecycleTask;
import net.javacrumbs.shedlock.core.SimpleLock;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleAccountProcessor;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleScheduling;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;

class CernHrLifecycleSchedulingTests {

  @TestConfiguration
  @EnableAspectJAutoProxy(proxyTargetClass = true)
  @EnableSchedulerLock(defaultLockAtMostFor = "PT2H")
  @Import(CernHrLifecycleScheduling.class)
  static class LockConfig {
  }

  @Test
  void registeredCronSkipsAccountScanWhenLifecycleLockIsHeld() {
    assertRegisteredCronUsesSharedLock(false);
  }

  @Test
  void registeredCronHoldsLockThroughHrSyncAndExpiration() {
    assertRegisteredCronUsesSharedLock(true);
  }

  private void assertRegisteredCronUsesSharedLock(boolean lockAvailable) {
    try (AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext()) {
      ctx.getEnvironment().setActiveProfiles("cern");
      LockProvider locks = mock(LockProvider.class);
      SimpleLock lock = mock(SimpleLock.class);
      when(locks.lock(any())).thenReturn(lockAvailable ? Optional.of(lock) : Optional.empty());
      ExpiredAccountsHandler expired = mock(ExpiredAccountsHandler.class);
      IamAccountRepository accounts = mock(IamAccountRepository.class);
      when(accounts.findByLabelPrefixAndName(any(), any(), any())).thenReturn(Page.empty());
      ctx.registerBean(LockProvider.class, () -> locks);
      ctx.registerBean(ExpiredAccountsHandler.class, () -> expired);
      ctx.registerBean(LifecycleProperties.class, LifecycleProperties::new);
      ctx.registerBean(CernAccountLifecycleTask.class);
      ctx.registerBean(IamAccountRepository.class, () -> accounts);
      ctx.registerBean(CernHrDBApiService.class, () -> mock(CernHrDBApiService.class));
      ctx.registerBean(CernHrLifecycleAccountProcessor.class,
          () -> mock(CernHrLifecycleAccountProcessor.class));
      ctx.registerBean(CernProperties.class, () -> new CernProperties());
      ctx.registerBean("cernHrLifecycleHandler", CernHrLifecycleHandler.class);
      ctx.register(LockConfig.class);
      ctx.refresh();

      ScheduledTaskRegistrar registrar = new ScheduledTaskRegistrar();
      ctx.getBean(CernHrLifecycleScheduling.class).configureTasks(registrar);
      assertEquals(1, registrar.getCronTaskList().size());
      registrar.getCronTaskList().get(0).getRunnable().run();

      verify(locks).lock(argThat(config -> "accountLifecycle".equals(config.getName())));
      if (lockAvailable) {
        InOrder order = inOrder(accounts, expired, lock);
        order.verify(accounts).findByLabelPrefixAndName(any(), any(), any());
        order.verify(expired).handleExpiredAccounts(java.util.Set.of());
        order.verify(lock).unlock();
      } else {
        verifyNoInteractions(accounts, expired, lock);
      }
    }
  }
}
