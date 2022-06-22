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
package it.infn.mw.iam.notification.service;

import java.util.Date;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.notification.NotificationDelivery;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamNotificationReceiver;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;

@Service
@ConditionalOnProperty(name = "notification.disable", havingValue = "true")
public class LoggingNotificationDelivery implements NotificationDelivery {

  public static final Logger LOG = LoggerFactory.getLogger(LoggingNotificationDelivery.class);

  protected final IamEmailNotificationRepository repo;
  protected final NotificationProperties properties;
  protected final TimeProvider timeProvider;

  @Autowired
  public LoggingNotificationDelivery(IamEmailNotificationRepository repo,
      NotificationProperties properties, TimeProvider provider) {

    this.repo = repo;
    this.properties = properties;
    this.timeProvider = provider;
  }

  protected void logEmailNotificationAndSetDelivered(IamEmailNotification e) {
    String receivers =
        e.getReceivers().stream().map(IamNotificationReceiver::getEmailAddress).collect(
            Collectors.joining(","));

    LOG.info("Email message [To:'{}' Subject:'{}' Body:'{}']", receivers, e.getSubject(),
        e.getBody());
    e.setDeliveryStatus(IamDeliveryStatus.DELIVERED);
    e.setLastUpdate(new Date(timeProvider.currentTimeMillis()));
    repo.save(e);
  }

  @Override
  public void sendPendingNotifications() {
    repo.findByDeliveryStatus(IamDeliveryStatus.PENDING)
      .forEach(this::logEmailNotificationAndSetDelivered);
  }

}
