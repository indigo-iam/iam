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

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.mitre.oauth2.service.DeviceCodeService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationDelivery;
import it.infn.mw.iam.notification.NotificationDeliveryTask;
import it.infn.mw.iam.notification.service.NotificationStoreService;

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

  @Autowired
  OAuth2TokenEntityService tokenEntityService;

  @Autowired
  ApprovedSiteService approvedSiteService;

  @Autowired
  NotificationStoreService notificationStoreService;

  @Autowired
  NotificationDelivery notificationDelivery;

  @Autowired
  IamAccountService accountService;

  @Autowired
  DeviceCodeService deviceCodeService;

  @Autowired
  NotificationDeliveryTask deliveryTask;

  @Autowired
  LifecycleProperties lifecycleProperties;

  @Autowired
  ExpiredAccountsHandler expiredAccountsHandler;

  @Value("${notification.disable}")
  boolean notificationDisabled;

  @Value("${notification.taskDelay}")
  long notificationTaskPeriodMsec;


  @Bean(destroyMethod = "shutdown")
  public ScheduledExecutorService taskScheduler() {
    return Executors.newSingleThreadScheduledExecutor();
  }

  @Scheduled(fixedDelayString = "${task.tokenCleanupPeriodMsec}", initialDelay = TEN_MINUTES_MSEC)
  public void clearExpiredTokens() {

    tokenEntityService.clearExpiredTokens();
  }

  @Scheduled(fixedDelayString = "${task.approvalCleanupPeriodMsec}",
      initialDelay = TEN_MINUTES_MSEC)
  public void clearExpiredSites() {

    approvedSiteService.clearExpiredSites();
  }

  @Scheduled(fixedDelay = THIRTY_SECONDS_MSEC, initialDelay = TEN_MINUTES_MSEC)
  public void clearExpiredNotifications() {
    notificationStoreService.clearExpiredNotifications();
  }

  @Scheduled(fixedDelayString = "${task.deviceCodeCleanupPeriodMsec}",
      initialDelay = TEN_MINUTES_MSEC)
  public void clearExpiredDeviceCodes() {
    deviceCodeService.clearExpiredDeviceCodes();
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
    taskRegistrar.setScheduler(taskScheduler());
    schedulePendingNotificationsDelivery(taskRegistrar);
    scheduledExpiredAccountsTask(taskRegistrar);
  }

}
