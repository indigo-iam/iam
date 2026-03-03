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

import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.gc.GarbageCollector;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.web.aup.AupReminderTask;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;
import it.infn.mw.iam.notification.NotificationDeliveryTask;
import it.infn.mw.iam.notification.service.NotificationStoreService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Configuration
@EnableScheduling
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
  private NotificationDeliveryTask deliveryTask;
  private LifecycleProperties lifecycleProperties;
  private ExpiredAccountsHandler expiredAccountsHandler;
  private AupReminderTask aupReminderTask;
  private ExecutorService taskScheduler;
  private IamClientRepository clientRepo;
  private ClientService clientService;
  private GarbageCollector garbageCollector;

  @Value("${notification.disable}")
  boolean notificationDisabled;

  @Value("${notification.taskDelay}")
  long notificationTaskPeriodMsec;

  public TaskConfig(NotificationStoreService notificationStoreService,
      NotificationDeliveryTask deliveryTask, LifecycleProperties lifecycleProperties,
      ExpiredAccountsHandler expiredAccountsHandler, AupReminderTask aupReminderTask,
      ExecutorService taskScheduler, IamClientRepository clientRepo, ClientService clientService,
      GarbageCollector garbageCollector) {

    this.notificationStoreService = notificationStoreService;
    this.deliveryTask = deliveryTask;
    this.lifecycleProperties = lifecycleProperties;
    this.expiredAccountsHandler = expiredAccountsHandler;
    this.aupReminderTask = aupReminderTask;
    this.taskScheduler = taskScheduler;
    this.clientRepo = clientRepo;
    this.clientService = clientService;
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

  @Scheduled(fixedDelay = ONE_DAY_MSEC, initialDelay = TEN_MINUTES_MSEC)
  public void disableExpiredClients() {
    List<ClientDetailsEntity> clients = clientRepo.findActiveClientsExpiredBefore(new Date());
    for (ClientDetailsEntity client : clients) {
      clientService.updateClientStatus(client, false, "expired_client_task");
    }
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
  }
}
