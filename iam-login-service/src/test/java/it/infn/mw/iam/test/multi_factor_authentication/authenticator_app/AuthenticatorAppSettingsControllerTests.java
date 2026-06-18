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

import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.DISABLE_URL_FOR_ACCOUNT_ID;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.notification.NotificationTestConfig;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.notification.MockNotificationDelivery;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class,
        NotificationTestConfig.class},
    webEnvironment = WebEnvironment.MOCK, properties = {"notification.disable=false"})
@AutoConfigureMockMvc
@Transactional
class AuthenticatorAppSettingsControllerTests extends MultiFactorTestSupport {

  @Autowired
  MockMvc mvc;
  @Autowired
  MockNotificationDelivery notificationDelivery;
  @Autowired
  IamEmailNotificationRepository notificationRepo;
  @MockBean
  IamAccountRepository accountRepository;
  @MockBean
  IamTotpMfaRepository totpMfaRepository;

  Clock clock;
  IamAccount testAccount;
  IamAccount mfaAccount;
  IamTotpMfa totp;

  @BeforeEach
  void setup() {

    clock = Clock.systemUTC();

    mfaAccount = getTotpMfaAccount(clock.instant());
    totp = getTotpMfaFor(mfaAccount, clock.instant());
    Mockito.when(accountRepository.findByUuid(mfaAccount.getUuid()))
      .thenReturn(Optional.of(mfaAccount));
    Mockito.when(totpMfaRepository.findByAccount(mfaAccount)).thenReturn(Optional.of(totp));
  }

  @AfterEach
  void tearDown() {
    notificationDelivery.clearDeliveredNotifications();
  }

  @Test
  @WithAnonymousUser
  void testDisableAuthenticatorAppNoAuthenticationFails() throws Exception {
    mvc.perform(delete(DISABLE_URL_FOR_ACCOUNT_ID, TOTP_UUID)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void testDisableAuthenticatorAppWorksForAdmin() throws Exception {
    mvc.perform(delete(DISABLE_URL_FOR_ACCOUNT_ID, TOTP_UUID)).andExpect(status().isOk());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void testConfirmationEmailSentOnMfaDisable() throws Exception {
    mvc.perform(delete(DISABLE_URL_FOR_ACCOUNT_ID, TOTP_UUID)).andExpect(status().isOk());

    List<IamEmailNotification> notifications =
        notificationRepo.findByNotificationType(IamNotificationType.MFA_DISABLE);

    assertEquals(1, notifications.size());
    assertEquals("[indigo-dc IAM] Multi-factor authentication (MFA) disabled",
        notifications.get(0).getSubject());

    notificationDelivery.sendPendingNotifications();

    assertThat(notificationDelivery.getDeliveredNotifications(), hasSize(1));
    IamEmailNotification message = notificationDelivery.getDeliveredNotifications().get(0);
    assertThat(message.getSubject(),
        equalTo("[indigo-dc IAM] Multi-factor authentication (MFA) disabled"));
  }

}
