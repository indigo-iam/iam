package it.infn.mw.iam.config;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import it.infn.mw.iam.notification.NotificationService;

@Configuration
@EnableScheduling
public class TaskConfig implements SchedulingConfigurer {

  public static final long ONE_SECOND_MSEC = 1000;
  public static final long TEN_SECONDS_MSEC = 10 * ONE_SECOND_MSEC;
  public static final long THIRTY_SECONDS_MSEC = 30 * ONE_SECOND_MSEC;
  public static final long ONE_MINUTE_MSEC = 60 * ONE_SECOND_MSEC;
  public static final long TEN_MINUTES_MSEC = 10 * ONE_MINUTE_MSEC;

  @Autowired
  OAuth2TokenEntityService tokenEntityService;

  @Autowired
  ApprovedSiteService approvedSiteService;

  @Autowired
  @Qualifier("defaultNotificationService")
  NotificationService notificationService;

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

  @Scheduled(fixedDelayString = "${notification.taskDelay}", initialDelay = TEN_SECONDS_MSEC)
  public void sendNotifications() {
    notificationService.sendPendingNotifications();
  }

  @Scheduled(fixedDelay = THIRTY_SECONDS_MSEC, initialDelay = TEN_MINUTES_MSEC)
  public void clearExpiredNotifications() {
    notificationService.clearExpiredNotifications();
  }

  @Override
  public void configureTasks(final ScheduledTaskRegistrar taskRegistrar) {

    taskRegistrar.setScheduler(taskScheduler());
  }

}
