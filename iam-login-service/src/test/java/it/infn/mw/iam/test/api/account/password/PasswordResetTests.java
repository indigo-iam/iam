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
package it.infn.mw.iam.test.api.account.password;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.password_reset.ResetPasswordDTO;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.notification.NotificationTestConfig;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.notification.MockNotificationDelivery;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;
import static it.infn.mw.iam.util.RegexUtil.PASSWORD_REGEX_MESSAGE_ERROR;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, NotificationTestConfig.class,
    CoreControllerTestSupport.class}, webEnvironment = WebEnvironment.MOCK)
@WithAnonymousUser
public class PasswordResetTests {

  @Autowired
  private PersistentUUIDTokenGenerator tokenGenerator;

  @Autowired
  private MockNotificationDelivery notificationDelivery;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void tearDown() {
    notificationDelivery.clearDeliveredNotifications();
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void testChangePassword() throws Exception {
    String testEmail = "test@iam.test";

    String newPassword = "Secure_P@ssw0rd!";

    mvc.perform(post("/iam/password-reset/token").param("email", testEmail))
      .andExpect(status().isOk());

    String resetToken = tokenGenerator.getLastToken();

    mvc.perform(head("/iam/password-reset/token/{token}", resetToken)).andExpect(status().isOk());

    ResetPasswordDTO request = new ResetPasswordDTO();
    request.setUpdatedPassword(newPassword);
    request.setToken(resetToken);

    mvc
      .perform(post("/iam/password-reset").contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isOk());

    mvc.perform(head("/iam/password-reset/token/{token}", resetToken))
      .andExpect(status().isNotFound());
  }

  @Test
  public void testChangePasswordWeak() throws Exception {
    String testEmail = "test@iam.test";

    String newPassword = "weakpassword";

    mvc.perform(post("/iam/password-reset/token").param("email", testEmail))
      .andExpect(status().isOk());

    String resetToken = tokenGenerator.getLastToken();

    mvc.perform(head("/iam/password-reset/token/{token}", resetToken)).andExpect(status().isOk());

    JsonObject jsonBody = new JsonObject();
    jsonBody.addProperty("updatedPassword", newPassword);
    jsonBody.addProperty("token", resetToken);

    mvc
      .perform(
          post("/iam/password-reset").contentType(APPLICATION_JSON).content(jsonBody.toString()))
      .andExpect(status().isBadRequest())
      .andExpect(MockMvcResultMatchers.content()
        .string("Invalid reset password: [resetPasswordDTO.updatedPassword : "
            + PASSWORD_REGEX_MESSAGE_ERROR + "]"));;
  }

  @Test
  public void testChangePasswordWithTokenJustUsed() throws Exception {
    String testEmail = "test@iam.test";

    String newPassword = "Secure_P@ssw0rd!";

    mvc.perform(post("/iam/password-reset/token").param("email", testEmail))
      .andExpect(status().isOk());

    String resetToken = tokenGenerator.getLastToken();

    mvc.perform(head("/iam/password-reset/token/{token}", resetToken)).andExpect(status().isOk());

    JsonObject jsonBody = new JsonObject();
    jsonBody.addProperty("updatedPassword", newPassword);
    jsonBody.addProperty("token", resetToken);

    mvc
      .perform(
          post("/iam/password-reset").contentType(APPLICATION_JSON).content(jsonBody.toString()))
      .andExpect(status().isOk());

    mvc
      .perform(
          post("/iam/password-reset").contentType(APPLICATION_JSON).content(jsonBody.toString()))
      .andExpect(status().is4xxClientError());
  }

  @Test
  public void testResetPasswordWithInvalidResetToken() throws Exception {

    String resetToken = "abcdefghilmnopqrstuvz";

    mvc.perform(head("/iam/password-reset/token/{token}", resetToken))
      .andExpect(status().isNotFound());

  }

  @Test
  public void testCreatePasswordResetTokenReturnsOkForUnknownAddress() throws Exception {

    String testEmail = "test@foo.bar";

    mvc.perform(post("/iam/password-reset/token").param("email", testEmail))
      .andExpect(status().isOk());

  }

  @Test
  public void testEmailValidationForPasswordResetTokenCreation() throws Exception {
    String invalidEmailAddress = "this_is_not_an_email";

    mvc.perform(post("/iam/password-reset/token").param("email", invalidEmailAddress))
      .andExpect(status().isBadRequest())
      .andExpect(MockMvcResultMatchers.content()
        .string("validation error: please specify a valid email address"));

  }

}
