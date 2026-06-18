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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.notification.MockNotificationDelivery;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    NotificationTestConfig.class}, webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(properties = {"notification.disable=true"})
class NotificationDisabledTests {

  static final String REGISTRATION_CREATE_ENDPOINT = "/registration/create";

  @Autowired
  MockNotificationDelivery notificationDelivery;

  @Value("${spring.mail.host}")
  String mailHost;

  @Value("${spring.mail.port}")
  Integer mailPort;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  IamAccountRepository accountRepository;

  @Autowired
  MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  MockMvc mvc;

  @BeforeEach
  void setUp() {
    mockOAuth2Filter.cleanupSecurityContext();
    notificationDelivery.clearDeliveredNotifications();
  }

  @AfterEach
  void tearDown() {
    mockOAuth2Filter.cleanupSecurityContext();
    notificationDelivery.clearDeliveredNotifications();
  }

  @Test
  void testDisableNotificationOption() throws Exception {
    RegistrationRequestDto req = new RegistrationRequestDto();

    req.setGivenname("testDisableNotificationOption");
    req.setFamilyname("User");
    req.setEmail("testDisableNotificationOption@example.org");
    req.setUsername("testdisablenotificationoption");
    req.setNotes("testDisableNotificationOption");

    String jsonReq = mapper.writeValueAsString(req);

    String response = mvc
      .perform(post(REGISTRATION_CREATE_ENDPOINT).content(jsonReq)
        .contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegistrationRequestDto savedRequest = mapper.readValue(response, RegistrationRequestDto.class);

    notificationDelivery.sendPendingNotifications();

    assertThat(notificationDelivery.getDeliveredNotifications(), hasSize(0));

    IamAccount account = accountRepository.findByUuid(savedRequest.getAccountId())
      .orElseThrow(() -> new AssertionError("Expected account not found!"));

    accountRepository.delete(account);
  }

}
