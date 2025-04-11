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
