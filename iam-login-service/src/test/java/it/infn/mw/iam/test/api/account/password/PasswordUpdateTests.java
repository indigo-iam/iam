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

import static it.infn.mw.iam.test.TestUtils.CLIENT_CRED_GRANT_CLIENT_ID;
import static it.infn.mw.iam.test.TestUtils.CLIENT_CRED_GRANT_CLIENT_SECRET;
import static it.infn.mw.iam.test.TestUtils.PASSWORD_GRANT_CLIENT_ID;
import static it.infn.mw.iam.test.TestUtils.PASSWORD_GRANT_CLIENT_SECRET;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.password_reset.PasswordUpdateController;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SpringBootTest(classes = IamLoginService.class)
@AutoConfigureMockMvc
class PasswordUpdateTests {

  private static final String USER_USERNAME = "password_tester_user";
  private static final String USER_PASSWORD = "password";
  private static final String USER_NAME = "TESTER";
  private static final String USER_SURNAME = "USER";
  private static final String USER_EMAIL = "password_tester_user@test.org";

  private static final String VALID_PASSWORD = "Secure_P@ssw0rd!";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private IamAccountRepository accountRepository;

  private IamAccount testUser;

  @BeforeEach
  void testSetup() {

    IamAccount account = IamAccount.newAccount();
    account.setActive(true);
    account.setUsername(USER_USERNAME);
    account.setPassword(USER_PASSWORD);
    account.getUserInfo().setGivenName(USER_NAME);
    account.getUserInfo().setFamilyName(USER_SURNAME);
    account.getUserInfo().setEmail(USER_EMAIL);
    account.getUserInfo().setEmailVerified(true);

    testUser = accountService.createAccount(account);
  }

  @AfterEach
  void testTeardown() {

    if (testUser != null) {
      accountService.deleteAccount(testUser);
    }
  }

  private String getAccessToken(MockHttpServletRequestBuilder request) throws Exception {

    String response = mvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token", is(not(emptyOrNullString()))))
      .andReturn()
      .getResponse()
      .getContentAsString();

    return objectMapper.readTree(response).get("access_token").asText();
  }

  private String getUserAccessToken(String password) throws Exception {

    return getAccessToken(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
      .param("grant_type", "password")
      .param("client_id", PASSWORD_GRANT_CLIENT_ID)
      .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
      .param("username", testUser.getUsername())
      .param("password", password));
  }

  private String getClientAccessToken() throws Exception {

    return getAccessToken(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
      .param("grant_type", "client_credentials")
      .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
      .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET));
  }

  private ResultActions updatePassword(String accessToken, String currentPassword,
      String newPassword) throws Exception {

    MockHttpServletRequestBuilder request =
        post(PasswordUpdateController.BASE_URL).with(csrf().asHeader())
          .contentType(MediaType.APPLICATION_FORM_URLENCODED);

    if (accessToken != null) {
      request.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
    }

    if (currentPassword != null) {
      request.param(PasswordUpdateController.CURRENT_PASSWORD, currentPassword);
    }

    if (newPassword != null) {
      request.param(PasswordUpdateController.UPDATED_PASSWORD, newPassword);
    }

    return mvc.perform(request);
  }

  @Test
  void testUpdatePassword() throws Exception {

    String accessToken = getUserAccessToken(USER_PASSWORD);

    updatePassword(accessToken, USER_PASSWORD, VALID_PASSWORD).andExpect(status().isOk());

    // Verify authentication with the updated password.
    getUserAccessToken(VALID_PASSWORD);
  }

  @Test
  void testUpdatePasswordWithMinLength() throws Exception {

    String newPassword = "S3crP@ss";
    String accessToken = getUserAccessToken(USER_PASSWORD);

    updatePassword(accessToken, USER_PASSWORD, newPassword).andExpect(status().isOk());

    getUserAccessToken(newPassword);

    updatePassword(accessToken, newPassword, "T0S#ort").andExpect(status().isBadRequest());
  }

  @Test
  void testUpdatePasswordFullAuthenticationRequired() throws Exception {

    updatePassword(null, USER_PASSWORD, VALID_PASSWORD).andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error").value("unauthorized"))
      .andExpect(jsonPath("$.error_description")
        .value("Full authentication is required to access this resource"));
  }

  @Test
  void testUpdateWrongPasswordProvided() throws Exception {

    String accessToken = getUserAccessToken(USER_PASSWORD);

    updatePassword(accessToken, "thisisnotthecurrentpassword", VALID_PASSWORD)
      .andExpect(status().isBadRequest());
  }

  @Test
  void testUpdatePasswordForbiddenAccess() throws Exception {

    String accessToken = getClientAccessToken();

    updatePassword(accessToken, USER_PASSWORD, VALID_PASSWORD).andExpect(status().isForbidden());
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"pass", "newweakpassword", "Password1", "Sjfyt-hdddW!"})
  void testUpdatePasswordRejectsInvalidPassword(String newPassword) throws Exception {

    String accessToken = getUserAccessToken(USER_PASSWORD);

    updatePassword(accessToken, USER_PASSWORD, newPassword).andExpect(status().isBadRequest());
  }

  @Test
  void testUpdatePasswordUserNotActive() throws Exception {

    String accessToken = getUserAccessToken(USER_PASSWORD);

    IamAccount account = accountRepository.findByUsername(testUser.getUsername())
      .orElseThrow(() -> new IllegalStateException("Test user not found"));

    account.setActive(false);
    accountRepository.save(account);

    updatePassword(accessToken, USER_PASSWORD, VALID_PASSWORD).andExpect(status().isUnauthorized())
      .andExpect(content()
        .string(containsString("User with uuid " + account.getUuid() + " is not active")));
  }
}
