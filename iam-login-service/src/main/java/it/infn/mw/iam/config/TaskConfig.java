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
package it.infn.mw.iam.config;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.gc.GarbageCollector;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.web.aup.AupReminderTask;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;
import it.infn.mw.iam.notification.NotificationDeliveryTask;
import it.infn.mw.iam.notification.service.NotificationStoreService;
import it.infn.mw.iam.registration.RegistrationRequestService;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;

@Configuration
@EnableScheduling
@EnableSchedulerLock(defaultLockAtMostFor = "20m")
@Profile({"prod", "dev"})
public class TaskConfig implements SchedulingConfigurer {

  public static final Logger LOG = LoggerFactory.getLogger(TaskConfig.class);

  public static final long ONE_SECOND_MSEC = 1000;
  public static final long TEN_SECONDS_MSEC = 10 * ONE_SECOND_MSEC;
  public static final long THIRTY_SECONDS_MSEC = 30 * ONE_SECOND_MSEC;
  public static final long ONE_MINUTE_MSEC = 60 * ONE_SECOND_MSEC;
  public static final long TEN_MINUTES_MSEC = 10 * ONE_MINUTE_MSEC;
  public static final long ONE_HOUR_MSEC = 60 * ONE_MINUTE_MSEC;
  public static final long ONE_DAY_MSEC = 24 * ONE_HOUR_MSEC;

  private NotificationStoreService notificationStoreService;
  private RegistrationRequestService registrationRequestService;
  private NotificationDeliveryTask deliveryTask;
  private LifecycleProperties lifecycleProperties;
  private ExpiredAccountsHandler expiredAccountsHandler;
  private AupReminderTask aupReminderTask;
  private ExecutorService taskScheduler;
  private GarbageCollector garbageCollector;

  @Value("${notification.disable}")
  boolean notificationDisabled;

  @Value("${notification.taskDelay}")
  long notificationTaskPeriodMsec;

  @Value("${iam.cleanup.expired.registration.expiry-days:7}")
  private long expiryDays;
  
  @Value("${iam.cleanup.expired.registration.enabled:false}")
  private boolean cleanupExpiredRegistrationCronScheduleEnabled;

  @Value("${iam.cleanup.expired.registration.cron:0 0 7 * * *}")
  private String cleanupExpiredRegistrationCronSchedule;

  public TaskConfig(NotificationStoreService notificationStoreService,
      RegistrationRequestService registrationRequestService,
      NotificationDeliveryTask deliveryTask, LifecycleProperties lifecycleProperties,
      ExpiredAccountsHandler expiredAccountsHandler, AupReminderTask aupReminderTask,
      ExecutorService taskScheduler, GarbageCollector garbageCollector) {

    this.notificationStoreService = notificationStoreService;
    this.registrationRequestService = registrationRequestService;
    this.deliveryTask = deliveryTask;
    this.lifecycleProperties = lifecycleProperties;
    this.expiredAccountsHandler = expiredAccountsHandler;
    this.aupReminderTask = aupReminderTask;
    this.taskScheduler = taskScheduler;
    this.garbageCollector = garbageCollector;
  }

  @Scheduled(fixedRateString = "${task.wellKnownCacheCleanupPeriodSecs:300}",
      timeUnit = TimeUnit.SECONDS)
  @CacheEvict(allEntries = true, cacheNames = IamWellKnownInfoProvider.CACHE_KEY)
  public void logWellKnownCacheEviction() {
    LOG.debug("well-known config cache evicted");
  }

  @Scheduled(fixedDelayString = "${task.tokenCleanupPeriodMsec}", initialDelay = TEN_MINUTES_MSEC)
  public void clearExpiredTokens() {

    garbageCollector.clearExpiredAccessTokens(100);
    garbageCollector.clearExpiredRefreshTokens(100);
    garbageCollector.clearOrphanedAuthenticationHolder(100);
  }

  @Scheduled(fixedDelayString = "${task.approvalCleanupPeriodMsec}",
      initialDelay = TEN_MINUTES_MSEC)
  public void clearExpiredSites() {

    garbageCollector.clearExpiredApprovedSites(100);
  }

  @Scheduled(fixedDelay = THIRTY_SECONDS_MSEC, initialDelay = TEN_MINUTES_MSEC)
  public void clearExpiredNotifications() {

    notificationStoreService.clearExpiredNotifications();
  }

  @Scheduled(fixedDelayString = "${task.deviceCodeCleanupPeriodMsec}",
      initialDelay = TEN_MINUTES_MSEC)
  public void clearExpiredDeviceCodes() {

    garbageCollector.clearExpiredDeviceCodes(100);
  }

  @Scheduled(fixedRateString = "${task.aupReminder:14400}", timeUnit = TimeUnit.SECONDS,
      initialDelay = ONE_MINUTE_MSEC)
  public void scheduledAupRemindersTask() {

    aupReminderTask.sendAupReminders();
  }

  public void scheduledCleanUpExpireRegistrationTask(final ScheduledTaskRegistrar taskRegistrar) {
    if (!cleanupExpiredRegistrationCronScheduleEnabled) {
      LOG.info("Expired registration request clean up task is disabled");
    } else {
      LOG.info("Scheduling expired registration request clean up task with schedule: {}", cleanupExpiredRegistrationCronSchedule);
      taskRegistrar.addCronTask(this::scheduledCleanUpExpireRegistration, cleanupExpiredRegistrationCronSchedule);
    }
  }

  private void scheduledCleanUpExpireRegistration() {
    LOG.info("Running cleanup with expiryDays= {}", expiryDays);
    Instant expiryTime = Instant.now().minus(expiryDays, ChronoUnit.DAYS);
    registrationRequestService.cleanupExpiredRegistrationRequests(expiryTime);
  }

  public void schedulePendingNotificationsDelivery(final ScheduledTaskRegistrar taskRegistrar) {

    if (notificationTaskPeriodMsec < 0) {
      LOG.info("Period notification delivery task will NOT be scheduled, since "
          + "notificationTaskPeriodMsec is a negative number: {}", notificationTaskPeriodMsec);
      return;
    }

    LOG.info("Scheduling pending notification delivery task to run every {} sec",
        TimeUnit.MILLISECONDS.toSeconds(notificationTaskPeriodMsec));

    taskRegistrar.addFixedRateTask(deliveryTask, notificationTaskPeriodMsec);
  }

  public void scheduledExpiredAccountsTask(final ScheduledTaskRegistrar taskRegistrar) {
    if (!lifecycleProperties.getAccount().getExpiredAccountsTask().isEnabled()) {
      LOG.info("Expired accounts task is disabled");
    } else {
      final String cronSchedule =
          lifecycleProperties.getAccount().getExpiredAccountsTask().getCronSchedule();
      LOG.info("Scheduling expired accounts handler task with schedule: {}", cronSchedule);
      taskRegistrar.addCronTask(expiredAccountsHandler, cronSchedule);
    }
  }

  @Override
  public void configureTasks(final ScheduledTaskRegistrar taskRegistrar) {
    taskRegistrar.setScheduler(taskScheduler);
    schedulePendingNotificationsDelivery(taskRegistrar);
    scheduledExpiredAccountsTask(taskRegistrar);
    scheduledCleanUpExpireRegistrationTask(taskRegistrar);
  }

  @Bean
  LockProvider lockProvider(DataSource dataSource) {
    return new JdbcTemplateLockProvider(JdbcTemplateLockProvider.Configuration.builder()
      .withJdbcTemplate(new JdbcTemplate(dataSource))
      .usingDbTime()
      .build());
  }
}
