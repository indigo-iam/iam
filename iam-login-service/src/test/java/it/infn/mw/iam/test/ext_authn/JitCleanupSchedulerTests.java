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
package it.infn.mw.iam.test.ext_authn;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.concurrent.TimeUnit;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import it.infn.mw.iam.config.JitCleanupScheduler;
import it.infn.mw.iam.config.JitProvisioningProperties;
import it.infn.mw.iam.core.user.IamAccountService;

@RunWith(MockitoJUnitRunner.class)
public class JitCleanupSchedulerTests {

  @InjectMocks
  private JitCleanupScheduler scheduler;

  @Mock
  private ScheduledTaskRegistrar taskRegistrar;

  @Mock
  private JitProvisioningProperties jitProperties;

  @Mock
  private IamAccountService accountService;

  @Test
  public void shouldNotScheduleTaskWhenJitProvisioningIsDisabled() {
    when(jitProperties.getEnabled()).thenReturn(false);

    scheduler.scheduleCleanupTask(taskRegistrar, jitProperties, accountService, "OIDC");

    verify(taskRegistrar, never()).addFixedRateTask(any(), anyLong());
  }

  @Test
  public void shouldNotScheduleTaskWhenCleanupIsDisabled() {
    when(jitProperties.getEnabled()).thenReturn(true);
    when(jitProperties.getCleanupTaskEnabled()).thenReturn(false);

    scheduler.scheduleCleanupTask(taskRegistrar, jitProperties, accountService, "OIDC");

    verify(taskRegistrar, never()).addFixedRateTask(any(), anyLong());
  }

  @Test
  public void shouldScheduleCleanupTaskWhenEnabled() {
    when(jitProperties.getEnabled()).thenReturn(true);
    when(jitProperties.getCleanupTaskEnabled()).thenReturn(true);
    when(jitProperties.getCleanupTaskPeriodSec()).thenReturn(3600L);
    when(jitProperties.getInactiveAccountLifetimeDays()).thenReturn(7);

    scheduler.scheduleCleanupTask(taskRegistrar, jitProperties, accountService, "OIDC");

    verify(taskRegistrar).addFixedRateTask(any(Runnable.class),
        eq(TimeUnit.SECONDS.toMillis(3600)));
  }
}
