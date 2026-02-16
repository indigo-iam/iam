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

import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.FixedRateTask;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import it.infn.mw.iam.api.aup.AupService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.config.oidc.OpenidFederationProperties;
import it.infn.mw.iam.core.gc.GarbageCollector;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.web.aup.AupReminderTask;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;
import it.infn.mw.iam.notification.NotificationDeliveryTask;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.notification.service.NotificationStoreService;

@Configuration
@EnableScheduling
public class TaskConfig implements SchedulingConfigurer {

  public static final Logger LOG = LoggerFactory.getLogger(TaskConfig.class);

  public static final long ONE_SECOND_MSEC = 1000;
  public static final long TEN_SECONDS_MSEC = 10 * ONE_SECOND_MSEC;
  public static final long THIRTY_SECONDS_MSEC = 30 * ONE_SECOND_MSEC;
  public static final long ONE_MINUTE_MSEC = 60 * ONE_SECOND_MSEC;
  public static final long TEN_MINUTES_MSEC = 10 * ONE_MINUTE_MSEC;
  public static final long ONE_HOUR_MSEC = 60 * ONE_MINUTE_MSEC;
  public static final long ONE_DAY_MSEC = 24 * ONE_HOUR_MSEC;

  private final TaskProperties taskProperties;
  private final OpenidFederationProperties oidFedProperties;
  private final NotificationProperties notificationProperties;
  private final AupService aupService;

  private NotificationStoreService notificationStoreService;
  private NotificationDeliveryTask deliveryTask;
  private LifecycleProperties lifecycleProperties;
  private ExpiredAccountsHandler expiredAccountsHandler;
  private AupReminderTask aupReminderTask;
  private ExecutorService taskScheduler;
  private ClientService clientService;
  private GarbageCollector garbageCollector;

  public TaskConfig(TaskProperties taskProperties,
      OpenidFederationProperties oidFedProperties, 
      NotificationProperties notificationProperties,
      AupService aupService,
      NotificationStoreService notificationStoreService, NotificationDeliveryTask deliveryTask,
      LifecycleProperties lifecycleProperties, ExpiredAccountsHandler expiredAccountsHandler,
      AupReminderTask aupReminderTask, ExecutorService taskScheduler,
      ClientService clientService,
      GarbageCollector garbageCollector) {

    this.taskProperties = taskProperties;
    this.oidFedProperties = oidFedProperties;
    this.notificationProperties = notificationProperties;
    this.aupService = aupService;
    this.notificationStoreService = notificationStoreService;
    this.deliveryTask = deliveryTask;
    this.lifecycleProperties = lifecycleProperties;
    this.expiredAccountsHandler = expiredAccountsHandler;
    this.aupReminderTask = aupReminderTask;
    this.taskScheduler = taskScheduler;
    this.clientService = clientService;
    this.garbageCollector = garbageCollector;
  }

  @Scheduled(fixedRateString = "${task.wellKnownCacheCleanupPeriodSecs:300}",
      timeUnit = TimeUnit.SECONDS)
  @CacheEvict(allEntries = true, cacheNames = IamWellKnownInfoProvider.CACHE_KEY)
  public void logWellKnownCacheEviction() {
    LOG.debug("well-known config cache evicted");
  }

  @Scheduled(fixedDelay = THIRTY_SECONDS_MSEC, initialDelay = TEN_MINUTES_MSEC)
  public void clearExpiredNotifications() {

    notificationStoreService.clearExpiredNotifications();
  }

  @Override
  public void configureTasks(final ScheduledTaskRegistrar taskRegistrar) {
    taskRegistrar.setScheduler(taskScheduler);
    schedulePendingNotificationsDelivery(taskRegistrar);
    scheduledExpiredAccountsTask(taskRegistrar);
    scheduleGarbageCollectorTasks(taskRegistrar);
    scheduleExpiredClientsTask(taskRegistrar);
    scheduleAupRemindersTask(taskRegistrar);
  }

  private void scheduleAupRemindersTask(ScheduledTaskRegistrar taskRegistrar) {

    Runnable aupRemindersTask = () -> {
      aupReminderTask.sendAupReminders();
    };

    if (aupService.findAup().isEmpty()) {
      LOG.info("Period AUP reminders delivery task will NOT be scheduled, since "
          + "an AUP is not defined");
      return;
    }
    if (taskProperties.getAupReminder() < 0) {
      LOG.info("Period AUP reminders delivery task will NOT be scheduled, since "
          + "task.aupReminders is a negative number: {}", taskProperties.getAupReminder());
      return;
    }
    LOG.info("Scheduling AUP reminders delivery task to run every {} sec",
        TimeUnit.MILLISECONDS.toSeconds(taskProperties.getAupReminder()));

    taskRegistrar.addFixedRateTask(
        new FixedRateTask(aupRemindersTask, taskProperties.getAupReminder(), ONE_MINUTE_MSEC));
  }

  public void schedulePendingNotificationsDelivery(final ScheduledTaskRegistrar taskRegistrar) {

    if (notificationProperties.getDisable()) {
      LOG.info("Period notification delivery task is disabled");
      return;
    }
    if (notificationProperties.getTaskDelay() < 0) {
      LOG.info("Period notification delivery task will NOT be scheduled, since "
          + "notificationTaskPeriodMsec is a negative number: {}", notificationProperties.getTaskDelay());
      return;
    }

    LOG.info("Scheduling pending notification delivery task to run every {} sec",
        TimeUnit.MILLISECONDS.toSeconds(notificationProperties.getTaskDelay()));

    taskRegistrar.addFixedRateTask(deliveryTask, notificationProperties.getTaskDelay());
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

  private void scheduleExpiredClientsTask(ScheduledTaskRegistrar taskRegistrar) {

    Runnable expiredClientsTask = () -> {
      clientService.disableExpiredClients();
    };

    if (oidFedProperties.isEnabled()) {
      LOG.info("Scheduling disable expired clients task to run every {} sec",
          TimeUnit.MILLISECONDS.toSeconds(ONE_DAY_MSEC));
      taskRegistrar
        .addFixedRateTask(new FixedRateTask(expiredClientsTask, ONE_DAY_MSEC, TEN_MINUTES_MSEC));
    }
  }

  private void scheduleGarbageCollectorTasks(ScheduledTaskRegistrar taskRegistrar) {

    Runnable expiredTokensTask = () -> {
      garbageCollector.clearExpiredAccessTokens(100);
      garbageCollector.clearExpiredRefreshTokens(100);
      garbageCollector.clearOrphanedAuthenticationHolder(100);
    };
    Runnable expiredApprovedSitesTask = () -> {
      garbageCollector.clearExpiredApprovedSites(100);
    };
    Runnable expiredDeviceCodesTask = () -> {
      garbageCollector.clearExpiredDeviceCodes(100);
    };

    // Expired Tokens Task
    if (taskProperties.getTokenCleanupPeriodMsec() < 0) {
      LOG.info(
          "Period expired token cleanup task will NOT be scheduled, since "
              + "task.tokenCleanupPeriodMsec is a negative number: {}",
          taskProperties.getTokenCleanupPeriodMsec());
    } else {
      LOG.info("Scheduling expired token cleanup task to run every {} sec",
          TimeUnit.MILLISECONDS.toSeconds(taskProperties.getTokenCleanupPeriodMsec()));
      taskRegistrar.addFixedRateTask(new FixedRateTask(expiredTokensTask,
          taskProperties.getTokenCleanupPeriodMsec(), TEN_MINUTES_MSEC));
    }

    // Expired Approved Sites Task
    if (taskProperties.getApprovalCleanupPeriodMsec() < 0) {
      LOG.info(
          "Period approved sites cleanup task will NOT be scheduled, since "
              + "task.approvalCleanupPeriodMsec is a negative number: {}",
          taskProperties.getTokenCleanupPeriodMsec());
    } else {
      LOG.info("Scheduling approved sites cleanup task to run every {} sec",
          TimeUnit.MILLISECONDS.toSeconds(taskProperties.getApprovalCleanupPeriodMsec()));
      taskRegistrar.addFixedRateTask(new FixedRateTask(expiredApprovedSitesTask,
          taskProperties.getApprovalCleanupPeriodMsec(), TEN_MINUTES_MSEC));
    }

    // Expired Device Codes Task
    if (taskProperties.getDeviceCodeCleanupPeriodMsec() < 0) {
      LOG.info(
          "Period device codes cleanup task will NOT be scheduled, since "
              + "task.deviceCodeCleanupPeriodMsec is a negative number: {}",
          taskProperties.getTokenCleanupPeriodMsec());
    } else {
      LOG.info("Scheduling device codes cleanup task to run every {} sec",
          TimeUnit.MILLISECONDS.toSeconds(taskProperties.getDeviceCodeCleanupPeriodMsec()));
      taskRegistrar.addFixedRateTask(new FixedRateTask(expiredDeviceCodesTask,
          taskProperties.getDeviceCodeCleanupPeriodMsec(), TEN_MINUTES_MSEC));
    }
  }
}
