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

import java.net.URISyntaxException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.mitre.oauth2.service.AuthenticationHolderEntityService;
import org.mitre.oauth2.service.DeviceCodeService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;

import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.IamOAuth2AuthorizationCodeService;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;
import it.infn.mw.iam.notification.NotificationDelivery;
import it.infn.mw.iam.notification.NotificationDeliveryTask;
import it.infn.mw.iam.notification.service.NotificationStoreService;

@Configuration
@EnableScheduling
@Profile({"prod", "dev"})
@SuppressWarnings("deprecation")
public class TaskConfig implements SchedulingConfigurer {

  public static final Logger LOG = LoggerFactory.getLogger(TaskConfig.class);

  public static final long ONE_SECOND_MSEC = 1000;
  public static final long TEN_SECONDS_MSEC = 10 * ONE_SECOND_MSEC;
  public static final long THIRTY_SECONDS_MSEC = 30 * ONE_SECOND_MSEC;
  public static final long ONE_MINUTE_MSEC = 60 * ONE_SECOND_MSEC;
  public static final long TWO_MINUTE_MSEC = 2 * 60 * ONE_SECOND_MSEC;
  public static final long THREE_MINUTE_MSEC = 3 * 60 * ONE_SECOND_MSEC;
  public static final long FOUR_MINUTE_MSEC = 4 * 60 * ONE_SECOND_MSEC;
  public static final long FIVE_MINUTE_MSEC = 5 * 60 * ONE_SECOND_MSEC;
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
  AuthorizationCodeServices authorizationCodeService;

  @Autowired
  AuthenticationHolderEntityService authenticationHolderEntityService;

  @Autowired
  NotificationDeliveryTask deliveryTask;

  @Autowired
  LifecycleProperties lifecycleProperties;

  @Autowired
  ExpiredAccountsHandler expiredAccountsHandler;

  @Autowired
  CacheManager cacheManager;

  @Autowired
  ExecutorService taskScheduler;

  @Value("${notification.disable}")
  boolean notificationDisabled;

  @Value("${notification.taskDelay}")
  long notificationTaskPeriodMsec;

  @Scheduled(fixedRateString = "${task.wellKnownCacheCleanupPeriodSecs}",
      timeUnit = TimeUnit.SECONDS)
  @CacheEvict(allEntries = true, cacheNames = IamWellKnownInfoProvider.CACHE_KEY)
  public void logWellKnownCacheEviction() {
    LOG.debug("well-known config cache evicted");
  }

  @Scheduled(fixedDelayString = "${task.tokenCleanupPeriodMsec}", initialDelay = FIVE_MINUTE_MSEC)
  public void clearExpiredTokens() {

    LOG.debug("Task clearExpiredTokens starting ...");
    tokenEntityService.clearExpiredTokens();
    LOG.debug("Task clearExpiredTokens ended");
  }

  @Scheduled(fixedDelayString = "${task.approvalCleanupPeriodMsec}", initialDelay = ONE_MINUTE_MSEC)
  public void clearExpiredSites() throws URISyntaxException {

    LOG.debug("Task clearExpiredSites starting ...");
    approvedSiteService.clearExpiredSites();
    LOG.debug("Task clearExpiredSites ended");
  }

  @Scheduled(fixedDelayString = "${task.deviceCodeCleanupPeriodMsec}",
      initialDelay = THREE_MINUTE_MSEC)
  public void clearExpiredDeviceCodes() {
    LOG.debug("Task clearExpiredDeviceCodes starting ...");
    deviceCodeService.clearExpiredDeviceCodes();
    LOG.debug("Task clearExpiredDeviceCodes ended");
  }

  @Scheduled(fixedDelayString = "${task.authorizationCodeCleanupPeriodMsec}",
      initialDelay = FOUR_MINUTE_MSEC)
  public void clearExpiredAuthorizationCodes() {
    LOG.debug("Task clearExpiredAuthorizationCodes starting ...");
    ((IamOAuth2AuthorizationCodeService) authorizationCodeService).clearExpiredAuthorizationCodes();
    LOG.debug("Task clearExpiredAuthorizationCodes ended");
  }

  @Scheduled(fixedDelayString = "${task.authenticationHolderCleanupPeriodMsec}",
      initialDelay = FIVE_MINUTE_MSEC)
  public void clearOrphanedAuthenticationHolder() {
    LOG.debug("Task clearOrphanedAuthenticationHolder starting ...");
    long deleted = authenticationHolderEntityService.clearOrphaned();
    LOG.debug("Deleted {} records.", deleted);
    LOG.debug("Task clearOrphanedAuthenticationHolder ended");
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
