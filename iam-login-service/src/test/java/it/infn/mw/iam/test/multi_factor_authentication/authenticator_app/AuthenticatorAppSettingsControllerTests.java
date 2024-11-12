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

package it.infn.mw.iam.test.multi_factor_authentication.authenticator_app;

import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.RESET_URL;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.hamcrest.Matchers.equalTo;

import java.util.List;
import java.util.Optional;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.notification.NotificationTestConfig;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.notification.MockNotificationDelivery;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = { IamLoginService.class, CoreControllerTestSupport.class,
        NotificationTestConfig.class }, webEnvironment = WebEnvironment.MOCK)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = { "notification.disable=false" })
public class AuthenticatorAppSettingsControllerTests extends MultiFactorTestSupport {
    private MockMvc mvc;
    @Autowired
    private WebApplicationContext context;
    @Autowired
    private MockNotificationDelivery notificationDelivery;
    @Autowired
    private IamEmailNotificationRepository notificationRepo;
    @MockBean
    private IamAccountRepository accountRepository;
    @MockBean
    private IamTotpMfaRepository totpMfaRepository;

    @Before
    public void setup() {
        when(accountRepository.findByUuid(TOTP_UUID)).thenReturn(Optional.of(TOTP_MFA_ACCOUNT));
        when(totpMfaRepository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(TOTP_MFA));

        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
    }

    @After
    public void tearDown() {
        notificationDelivery.clearDeliveredNotifications();
    }

    @Test
    @WithAnonymousUser
    public void testResetAuthenticatorAppNoAuthenticationFails() throws Exception {
        mvc.perform(delete(RESET_URL, TOTP_UUID))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void testResetAuthenticatorAppWorksForAdmin() throws Exception {
        mvc.perform(delete(RESET_URL, TOTP_UUID))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void testConfirmationEmailSentOnMfaReset() throws Exception {
        mvc.perform(delete(RESET_URL, TOTP_UUID))
                .andExpect(status().isOk());

        List<IamEmailNotification> notifications = notificationRepo
                .findByNotificationType(IamNotificationType.MFA_RESET);

        assertEquals(1, notifications.size());
        assertEquals("[indigo-dc IAM] Multi-factor authentication (MFA) reset", notifications.get(0).getSubject());

        notificationDelivery.sendPendingNotifications();

        assertThat(notificationDelivery.getDeliveredNotifications(), hasSize(1));
        IamEmailNotification message = notificationDelivery.getDeliveredNotifications().get(0);
        assertThat(message.getSubject(), equalTo("[indigo-dc IAM] Multi-factor authentication (MFA) reset"));
    }

}
