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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import it.infn.mw.iam.config.TaskConfig;
import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.lifecycle.cern.CernAccountLifecycleTask;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler;

class CernAccountLifecycleTaskTests {

  private final CernProperties cern = new CernProperties();
  private final LifecycleProperties lifecycle = new LifecycleProperties();
  private final CernHrLifecycleHandler hr = mock(CernHrLifecycleHandler.class);
  private final ExpiredAccountsHandler expired = mock(ExpiredAccountsHandler.class);
  private final CernAccountLifecycleTask task =
      new CernAccountLifecycleTask(cern, lifecycle, hr, expired);

  @Test
  void expirationReceivesOnlyFailuresFromCurrentSynchronization() {
    Set<String> failed = Set.of("failed-account");
    when(hr.synchronizeAccounts()).thenReturn(failed).thenReturn(Set.of());

    task.run();
    task.run();

    InOrder order = inOrder(hr, expired);
    order.verify(hr).synchronizeAccounts();
    order.verify(expired).handleExpiredAccounts(failed);
    order.verify(hr).synchronizeAccounts();
    order.verify(expired).handleExpiredAccounts(Set.of());
  }

  @Test
  void incompleteScanPreventsExpiration() {
    when(hr.synchronizeAccounts()).thenThrow(new IllegalStateException("Database unavailable"));

    assertThrows(IllegalStateException.class, task::run);

    verifyNoInteractions(expired);
  }

  @Test
  void disabledExpirationStillAllowsHrSynchronization() {
    lifecycle.getAccount().getExpiredAccountsTask().setEnabled(false);

    task.run();

    verify(hr).synchronizeAccounts();
    verifyNoInteractions(expired);
  }

  @Test
  void enabledHrReplacesIndependentExpirationCron() {
    ScheduledTaskRegistrar registrar = registerExpiration(Optional.of(task));

    assertEquals(0, registrar.getCronTaskList().size());
  }

  @Test
  void disabledHrRetainsIndependentExpirationCron() {
    cern.getTask().setEnabled(false);
    ScheduledTaskRegistrar registrar = registerExpiration(Optional.of(task));

    assertEquals(1, registrar.getCronTaskList().size());
    assertSame(expired, registrar.getCronTaskList().get(0).getRunnable());
  }

  @Test
  void nonCernDeploymentRetainsIndependentExpirationCron() {
    ScheduledTaskRegistrar registrar = registerExpiration(Optional.empty());

    assertEquals(1, registrar.getCronTaskList().size());
    assertSame(expired, registrar.getCronTaskList().get(0).getRunnable());
  }

  private ScheduledTaskRegistrar registerExpiration(Optional<CernAccountLifecycleTask> cernTask) {
    TaskConfig config = new TaskConfig(null, null, null, null, lifecycle, expired,
        null, null, null, cernTask);
    ScheduledTaskRegistrar registrar = new ScheduledTaskRegistrar();
    config.scheduledExpiredAccountsTask(registrar);
    return registrar;
  }
}
