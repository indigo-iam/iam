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

  @Autowired
  OAuth2TokenEntityService tokenEntityService;

  @Autowired
  ApprovedSiteService approvedSiteService;

  @Autowired
  @Qualifier("defaultNotificationService")
  NotificationService notificationService;

  @Bean(destroyMethod = "shutdown")
  public ScheduledExecutorService taskScheduler() {

    // Do we need more than one executor here?
    return Executors.newSingleThreadScheduledExecutor();
  }

  @Scheduled(fixedDelay = 60000 * 5, initialDelay = 60000 * 10)
  public void clearExpiredTokens() {

    tokenEntityService.clearExpiredTokens();
  }

  @Scheduled(fixedDelay = 30000, initialDelay = 60000)
  public void clearExpiredSites() {

    approvedSiteService.clearExpiredSites();
  }

  @Scheduled(fixedDelayString = "${notification.taskDelay}", initialDelay = 10000)
  public void sendNotifications() {
    notificationService.sendPendingNotifications();
  }

  @Scheduled(fixedDelay = 30000, initialDelay = 60000)
  public void clearExpiredNotifications() {
    notificationService.clearExpiredNotifications();
  }

  @Override
  public void configureTasks(final ScheduledTaskRegistrar taskRegistrar) {

    taskRegistrar.setScheduler(taskScheduler());
  }

}
