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
package it.infn.mw.iam.notification;

import java.util.List;
import java.util.Map;

import freemarker.template.Configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.notification.service.resolver.AdminNotificationDeliveryStrategy;
import it.infn.mw.iam.notification.service.resolver.GroupManagerNotificationDeliveryStrategy;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;

@Service
public class PersistentNotificationFactory extends TransientNotificationFactory {

  final IamEmailNotificationRepository repo;

  @Autowired
  public PersistentNotificationFactory(Configuration fm, NotificationProperties np,
                                       IamEmailNotificationRepository repo, AdminNotificationDeliveryStrategy ands,
                                       GroupManagerNotificationDeliveryStrategy gmds) {
    super(fm, np, ands, gmds);
    this.repo = repo;
  }

  @Override
  protected IamEmailNotification createMessage(String template, Map<String, Object> model,
      IamNotificationType messageType, String subject, List<String> receiverAddresses) {

    IamEmailNotification message =
        super.createMessage(template, model, messageType, subject, receiverAddresses);

    return repo.save(message);
  }

}
