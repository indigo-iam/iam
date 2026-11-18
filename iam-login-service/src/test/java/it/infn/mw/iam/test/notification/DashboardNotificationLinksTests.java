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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.Collections;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.test.util.ReflectionTestUtils;

import freemarker.template.Configuration;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.dashboard.DashboardUrlResolver;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.notification.TransientNotificationFactory;
import it.infn.mw.iam.notification.service.resolver.AdminNotificationDeliveryStrategy;
import it.infn.mw.iam.notification.service.resolver.GroupManagerNotificationDeliveryStrategy;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamGroupRequest;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

class DashboardNotificationLinksTests {

  @ParameterizedTest
  @CsvSource({
      "true, https://iam.example, /ui, https://iam.example/dashboard#!/requests, https://iam.example/dashboard#!/requests",
      "true, https://iam.example/, /ui/, https://iam.example/dashboard#!/requests, https://iam.example/dashboard#!/requests",
      "false, https://iam.example, /ui, https://iam.example/ui/requests, https://iam.example/ui/requests",
      "false, https://iam.example/, /ui/, https://iam.example/ui/requests, https://iam.example/ui/requests",
      "false, https://iam.example/iam/, /ui/, https://iam.example/iam/ui/requests, https://iam.example/iam/ui/requests",
      "false, https://iam.example/, /, https://iam.example/requests, https://iam.example/requests"})
  void resolvesAndRendersBothNotificationLinks(boolean legacyEnabled, String baseUrl,
      String basePath, String registrationUrl, String groupUrl) {

    IamProperties iam = new IamProperties();
    iam.setBaseUrl(baseUrl);
    iam.getDashboard().setLegacyEnabled(legacyEnabled);
    iam.getDashboard().setBasePath(basePath);
    DashboardUrlResolver urls = new DashboardUrlResolver(iam);
    assertEquals(registrationUrl, urls.registrationRequestsUrl());
    assertEquals(groupUrl, urls.groupRequestsUrl());

    Configuration templates = new Configuration(Configuration.VERSION_2_3_31);
    templates.setClassLoaderForTemplateLoading(getClass().getClassLoader(), "/email-templates");
    templates.setDefaultEncoding("UTF-8");

    NotificationProperties notifications = mock(NotificationProperties.class);
    when(notifications.getSubjectPrefix()).thenReturn("IAM");
    when(notifications.getSubject())
      .thenReturn(Collections.singletonMap("adminHandleRequest", "New request"));

    AdminNotificationDeliveryStrategy admins = mock(AdminNotificationDeliveryStrategy.class);
    when(admins.resolveAdminEmailAddresses())
      .thenReturn(Collections.singletonList("admin@example.org"));
    GroupManagerNotificationDeliveryStrategy managers =
        mock(GroupManagerNotificationDeliveryStrategy.class);

    TransientNotificationFactory factory = new TransientNotificationFactory(Clock.systemUTC(),
        templates, notifications, admins, managers, urls);
    ReflectionTestUtils.setField(factory, "organisationName", "Test organisation");

    IamRegistrationRequest registration = mock(IamRegistrationRequest.class, RETURNS_DEEP_STUBS);
    when(registration.getAccount().getUserInfo().getName()).thenReturn("Test User");
    when(registration.getAccount().getUsername()).thenReturn("test");
    when(registration.getAccount().getUserInfo().getEmail()).thenReturn("test@example.org");
    when(registration.getNotes()).thenReturn("Registration notes");

    IamGroupRequest group = mock(IamGroupRequest.class, RETURNS_DEEP_STUBS);
    when(group.getAccount().getUserInfo().getName()).thenReturn("Test User");
    when(group.getAccount().getUsername()).thenReturn("test");
    when(group.getGroup().getName()).thenReturn("test-group");
    when(group.getNotes()).thenReturn("Group notes");
    when(managers.resolveGroupManagersEmailAddresses(group.getGroup()))
      .thenReturn(Collections.singletonList("manager@example.org"));

    assertContainsLink(factory.createAdminHandleRequestMessage(registration), registrationUrl);
    assertContainsLink(factory.createAdminHandleGroupRequestMessage(group), groupUrl);
  }

  private void assertContainsLink(IamEmailNotification message, String url) {
    assertNotNull(message, "Template rendering must succeed");
    assertTrue(message.getBody().lines().anyMatch(url::equals), message.getBody());
  }
}
