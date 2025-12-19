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
package it.infn.mw.iam.test.oauth.revocation;

import static org.hamcrest.Matchers.equalTo;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
class RevocationEndpointTests extends EndpointsTestUtils {

  private static final String INVALID_TOKEN_VALUE = "not-a-token";

  private String accessToken;
  private String refreshToken;

  @BeforeEach
  void setup() throws Exception {

    TokenEndpointResponse tokenResponse = getPasswordToken("openid profile offline_access");
    accessToken = tokenResponse.accessToken();
    refreshToken = tokenResponse.refreshToken();
  }

  @Test
  void testRevocationEnpointRequiresClientAuth() throws Exception {

    mvc
      .perform(post(REVOCATION_ENDPOINT).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN, INVALID_TOKEN_VALUE))
      .andExpect(status().isUnauthorized());
  }

  @Test
  void testRevokeInvalidTokenReturns200() throws Exception {

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN, INVALID_TOKEN_VALUE))
      .andExpect(status().isOk());
  }

  @Test
  void testRevokeAccessTokenUnauthorizedForUsersAndAdmins() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.ACCESS_TOKEN.name())
            .param(OAuth2ParameterNames.TOKEN, accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(TEST_USERNAME, TEST_PASSWORD))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.ACCESS_TOKEN.name())
        .param(OAuth2ParameterNames.TOKEN, accessToken))
      .andExpect(status().isUnauthorized());

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(ADMIN_USERNAME, ADMIN_PASSWORD))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.ACCESS_TOKEN.name())
        .param(OAuth2ParameterNames.TOKEN, accessToken))
      .andExpect(status().isUnauthorized());
  }

  @Test
  void testRevokeRefreshTokenUnauthorizedForUsersAndAdmins() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.REFRESH_TOKEN.name())
            .param(OAuth2ParameterNames.TOKEN, refreshToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(TEST_USERNAME, TEST_PASSWORD))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.REFRESH_TOKEN.name())
        .param(OAuth2ParameterNames.TOKEN, refreshToken))
      .andExpect(status().isUnauthorized());

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(ADMIN_USERNAME, ADMIN_PASSWORD))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.REFRESH_TOKEN.name())
        .param(OAuth2ParameterNames.TOKEN, refreshToken))
      .andExpect(status().isUnauthorized());
  }

  @Test
  void testRevokeAccessTokenWorks() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.ACCESS_TOKEN.name())
            .param(OAuth2ParameterNames.TOKEN, accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.ACCESS_TOKEN.name())
        .param(OAuth2ParameterNames.TOKEN, accessToken))
      .andExpect(status().isOk());

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.ACCESS_TOKEN.name())
            .param(OAuth2ParameterNames.TOKEN, accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
  }

  @Test
  void testRevokeAccessTokenWorksWithInvalidToken() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.ACCESS_TOKEN.name())
            .param(OAuth2ParameterNames.TOKEN, INVALID_TOKEN_VALUE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.ACCESS_TOKEN.name())
        .param(OAuth2ParameterNames.TOKEN, INVALID_TOKEN_VALUE))
      .andExpect(status().isOk());
  }

  @Test
  void testRevokeAccessTokenIsForbiddenForNonIssuerClients() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.ACCESS_TOKEN.name())
            .param(OAuth2ParameterNames.TOKEN, accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));

    mvc
      .perform(post(REVOCATION_ENDPOINT)
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.ACCESS_TOKEN.name())
        .param(OAuth2ParameterNames.TOKEN, accessToken))
      .andExpect(status().isForbidden());
  }

  @Test
  void testRevokeRefreshTokenWorks() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.REFRESH_TOKEN.name())
            .param(OAuth2ParameterNames.TOKEN, refreshToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.REFRESH_TOKEN.name())
        .param(OAuth2ParameterNames.TOKEN, refreshToken))
      .andExpect(status().isOk());

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.REFRESH_TOKEN.name())
            .param(OAuth2ParameterNames.TOKEN, refreshToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
  }

  @Test
  void testRevokeRefreshTokenWorksWithInvalidToken() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.REFRESH_TOKEN.name())
            .param(OAuth2ParameterNames.TOKEN, INVALID_TOKEN_VALUE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.REFRESH_TOKEN.name())
        .param(OAuth2ParameterNames.TOKEN, INVALID_TOKEN_VALUE))
      .andExpect(status().isOk());
  }

  @Test
  void testRevokeRefreshTokenIsDisabledButOkForNonIssuerClients() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.REFRESH_TOKEN.name())
            .param(OAuth2ParameterNames.TOKEN, refreshToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));


    mvc
      .perform(post(REVOCATION_ENDPOINT)
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.REFRESH_TOKEN.name())
        .param(OAuth2ParameterNames.TOKEN, refreshToken))
      .andExpect(status().isForbidden());

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenTypeHint.REFRESH_TOKEN.name())
            .param(OAuth2ParameterNames.TOKEN, refreshToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
  }
}
