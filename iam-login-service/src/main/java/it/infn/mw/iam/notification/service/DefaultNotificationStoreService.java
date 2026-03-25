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

import java.time.Clock;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.time.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;

@Service
public class DefaultNotificationStoreService implements NotificationStoreService {

  public static final Logger LOG = LoggerFactory
      .getLogger(DefaultNotificationStoreService.class);
  
  final IamEmailNotificationRepository repo;
  final Clock clock;
  final NotificationProperties properties;

  public DefaultNotificationStoreService(IamEmailNotificationRepository repo,
      Clock clock, NotificationProperties properties) {
    this.repo = repo;
    this.clock = clock;
    this.properties = properties;
  }

  @Override
  public void clearExpiredNotifications() {
    Date currentTime = Date.from(clock.instant());
    Date threshold = DateUtils.addDays(currentTime, -properties.getCleanupAge());

    List<IamEmailNotification> messageList =
        repo.findByStatusWithUpdateTime(IamDeliveryStatus.DELIVERED, threshold);

    if (!messageList.isEmpty()) {
      repo.deleteAll(messageList);
      LOG.info("Deleted {} messages in status {} older than {}", messageList.size(),
          IamDeliveryStatus.DELIVERED, threshold);
    }
  }


  @Override
  public int countPendingNotifications() {
    return repo.countByDeliveryStatus(IamDeliveryStatus.PENDING);
  }

  @Override
  public void clearAllNotifications() {
    repo.deleteAll();
  }

}
