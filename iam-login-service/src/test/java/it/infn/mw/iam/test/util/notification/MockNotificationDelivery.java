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
package it.infn.mw.iam.test.util.notification;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.notification.service.LoggingNotificationDelivery;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;

public class MockNotificationDelivery extends LoggingNotificationDelivery {

  List<IamEmailNotification> deliveredNotifications = new LinkedList<>();

  public MockNotificationDelivery(IamEmailNotificationRepository repo,
      NotificationProperties properties, TimeProvider provider) {
    super(repo, properties, provider);
  }

  protected void deliverPendingNotification(IamEmailNotification e) {
    e.setDeliveryStatus(IamDeliveryStatus.DELIVERED);
    e.setLastUpdate(new Date(timeProvider.currentTimeMillis()));
    repo.save(e);
    deliveredNotifications.add(e);
  }

  @Override
  public void sendPendingNotifications() {
    if (!properties.getDisable()) {
      repo.findByDeliveryStatus(IamDeliveryStatus.PENDING)
        .forEach(this::deliverPendingNotification);
    }
  }

  public List<IamEmailNotification> getDeliveredNotifications() {
    return deliveredNotifications;
  }

  public void clearDeliveredNotifications() {
    deliveredNotifications.clear();
  }
}
