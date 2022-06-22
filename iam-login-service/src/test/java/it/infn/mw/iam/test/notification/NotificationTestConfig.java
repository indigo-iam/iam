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
package it.infn.mw.iam.test.notification;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.test.util.MockTimeProvider;
import it.infn.mw.iam.test.util.notification.MockNotificationDelivery;

@Configuration
public class NotificationTestConfig {

  @Bean
  public MockTimeProvider timeProvider() {
    return new MockTimeProvider();
  }

  @Bean
  @Primary
  public MockNotificationDelivery notificationDelivery(IamEmailNotificationRepository repo,
      NotificationProperties properties) {
    return new MockNotificationDelivery(repo, properties, timeProvider());
  }

}
