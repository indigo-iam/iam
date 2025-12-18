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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.NestedServletException;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.notification.MockNotificationDelivery;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    NotificationTestConfig.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@Transactional
@WithAnonymousUser
@TestPropertySource(
    properties = {"notification.disable=false", "spring.freemarker.template-loader-path=/invalid/"})
class RegistrationFlowFailTests {

  @Value("${spring.mail.host}")
  String mailHost;

  @Value("${spring.mail.port}")
  Integer mailPort;

  @Value("${iam.organisation.name}")
  String organisationName;

  @Value("${iam.baseUrl}")
  String baseUrl;

  @Autowired
  MockNotificationDelivery notificationDelivery;

  @Autowired
  MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  WebApplicationContext context;

  @Autowired
  ObjectMapper mapper;

  MockMvc mvc;

  @BeforeEach
  void setUp() {
    mvc =
        MockMvcBuilders.webAppContextSetup(context).alwaysDo(log()).apply(springSecurity()).build();
  }

  @AfterEach
  void tearDown() {
    mockOAuth2Filter.cleanupSecurityContext();
    notificationDelivery.clearDeliveredNotifications();
  }

  @Test
  void testSendWithEmptyQueue() {
    notificationDelivery.sendPendingNotifications();
    assertThat(notificationDelivery.getDeliveredNotifications(), hasSize(0));
  }

  @Test
  void testBadTemplateDir() {
    String username = "baddir_flow";

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Badddir flow");
    request.setFamilyname("Test");
    request.setEmail("Baddir@example.com");
    request.setUsername(username);
    request.setNotes("Some short notes...");

    assertThrows(NestedServletException.class,
        () -> mvc
          .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
            .content(mapper.writeValueAsString(request)))
          .andExpect(status().isInternalServerError()));
  }
}
