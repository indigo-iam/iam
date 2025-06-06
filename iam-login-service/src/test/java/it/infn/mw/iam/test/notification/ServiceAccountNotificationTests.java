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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.notification.MockNotificationDelivery;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = { IamLoginService.class, CoreControllerTestSupport.class,
                NotificationTestConfig.class }, webEnvironment = WebEnvironment.MOCK)
@WithAnonymousUser
@TestPropertySource(properties = { "notification.disable=false" })
public class ServiceAccountNotificationTests {

        @Autowired
        private MockNotificationDelivery notificationDelivery;

        @Autowired
        private MockOAuth2Filter mockOAuth2Filter;

        @Autowired
        private WebApplicationContext context;

        @Autowired
        private ObjectMapper mapper;

        @Autowired
        private IamAccountRepository iamAccountRepo;

        @Autowired
        private IamEmailNotificationRepository notificationRepo;

        private MockMvc mvc;

        @Before
        public void setUp() {
                mvc = MockMvcBuilders.webAppContextSetup(context).alwaysDo(log()).apply(springSecurity()).build();
        }

        @After
        public void tearDown() {
                mockOAuth2Filter.cleanupSecurityContext();
                notificationDelivery.clearDeliveredNotifications();
        }

        @Test
        @WithMockUser(username = "admin", roles = { "ADMIN", "USER" })
        public void testEmailSentForSettingServiceAccount() throws Exception {
                IamAccount testUser = iamAccountRepo.findByUsername("test")
                                .orElseThrow(() -> new AssertionError("Expected test user not found"));
                ScimUser user = ScimUser.builder().serviceAccount(true).build();

                ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder().replace(user).build();

                mvc.perform(patch("/scim/Users/{id}", testUser.getUuid())
                                .content(mapper.writeValueAsString(patchRequest))
                                .contentType("application/scim+json;charset=UTF-8"))
                                .andExpect(status().isNoContent());
                List<IamEmailNotification> notifications = notificationRepo
                                .findByNotificationType(IamNotificationType.SET_SERVICE_ACCOUNT);

                assertEquals(1, notifications.size());
                assertEquals("[indigo-dc IAM] Account set as service account", notifications.get(0).getSubject());

                notificationDelivery.sendPendingNotifications();

                assertThat(notificationDelivery.getDeliveredNotifications(), hasSize(1));
                IamEmailNotification message = notificationDelivery.getDeliveredNotifications().get(0);

                assertThat(message.getSubject(), equalTo("[indigo-dc IAM] Account set as service account"));

                assertThat(message.getReceivers(), hasSize(1));
                assertThat(message.getReceivers().get(0).getEmailAddress(),
                                equalTo(testUser.getUserInfo().getEmail()));

                notificationDelivery.clearDeliveredNotifications();
        }

        @Test
        @WithMockUser(username = "admin", roles = { "ADMIN", "USER" })
        public void testEmailSentForRevokingServiceAccount() throws Exception {
                IamAccount testUser = iamAccountRepo.findByUsername("test")
                                .orElseThrow(() -> new AssertionError("Expected test user not found"));
                testUser.setServiceAccount(true);
                iamAccountRepo.save(testUser);

                ScimUser user = ScimUser.builder().serviceAccount(false).build();

                ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder().replace(user).build();

                mvc.perform(patch("/scim/Users/{id}", testUser.getUuid())
                                .content(mapper.writeValueAsString(patchRequest))
                                .contentType("application/scim+json;charset=UTF-8"))
                                .andExpect(status().isNoContent());
                List<IamEmailNotification> notifications = notificationRepo
                                .findByNotificationType(IamNotificationType.REVOKE_SERVICE_ACCOUNT);

                assertEquals(1, notifications.size());
                assertEquals("[indigo-dc IAM] Account's service account status revoked",
                                notifications.get(0).getSubject());

                notificationDelivery.sendPendingNotifications();

                assertThat(notificationDelivery.getDeliveredNotifications(), hasSize(1));
                IamEmailNotification message = notificationDelivery.getDeliveredNotifications().get(0);

                assertThat(message.getSubject(), equalTo("[indigo-dc IAM] Account's service account status revoked"));

                assertThat(message.getReceivers(), hasSize(1));
                assertThat(message.getReceivers().get(0).getEmailAddress(),
                                equalTo(testUser.getUserInfo().getEmail()));

                notificationDelivery.clearDeliveredNotifications();
        }

}
