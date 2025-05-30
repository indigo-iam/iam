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
package it.infn.mw.iam.test.oauth.revoke;

import static it.infn.mw.iam.core.oauth.IamRevocationEndpoint.TOKEN_PARAM;
import static it.infn.mw.iam.core.oauth.IamRevocationEndpoint.TOKEN_TYPE_HINT_PARAM;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class RevocationEndpointTests extends EndpointsTestUtils {

  private static final String INVALID_TOKEN_VALUE = "not-a-token";

  private String accessToken;
  private String refreshToken;

  @Before
  public void setup() throws Exception {
    DefaultOAuth2AccessToken tokenResponse =
        getPasswordTokenResponse("openid profile offline_access");
    accessToken = tokenResponse.getValue();
    refreshToken = tokenResponse.getRefreshToken().getValue();
  }

  @Test
  public void testRevocationEnpointRequiresClientAuth() throws Exception {
    mvc
      .perform(post(REVOCATION_ENDPOINT).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_PARAM, INVALID_TOKEN_VALUE))
      .andExpect(status().isUnauthorized());
  }

  @Test
  public void testRevokeInvalidTokenReturns200() throws Exception {
    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_PARAM, INVALID_TOKEN_VALUE))
      .andExpect(status().isOk());
  }

  @Test
  public void testRevokeAccessTokenUnauthorizedForUsersAndAdmins() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.ACCESS_TOKEN.name())
            .param(TOKEN_PARAM, accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));


    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(TEST_USERNAME, TEST_PASSWORD))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.ACCESS_TOKEN.name())
        .param(TOKEN_PARAM, accessToken))
      .andExpect(status().isUnauthorized());

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(ADMIN_USERNAME, ADMIN_PASSWORD))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.ACCESS_TOKEN.name())
        .param(TOKEN_PARAM, accessToken))
      .andExpect(status().isUnauthorized());
  }

  @Test
  public void testRevokeRefreshTokenUnauthorizedForUsersAndAdmins() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.REFRESH_TOKEN.name())
            .param(TOKEN_PARAM, refreshToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));


    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(TEST_USERNAME, TEST_PASSWORD))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.REFRESH_TOKEN.name())
        .param(TOKEN_PARAM, refreshToken))
      .andExpect(status().isUnauthorized());

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(ADMIN_USERNAME, ADMIN_PASSWORD))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.REFRESH_TOKEN.name())
        .param(TOKEN_PARAM, refreshToken))
      .andExpect(status().isUnauthorized());
  }

  @Test
  public void testRevokeAccessTokenWorks() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.ACCESS_TOKEN.name())
            .param(TOKEN_PARAM, accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));


    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.ACCESS_TOKEN.name())
        .param(TOKEN_PARAM, accessToken))
      .andExpect(status().isOk());

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.ACCESS_TOKEN.name())
            .param(TOKEN_PARAM, accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
  }

  @Test
  public void testRevokeAccessTokenWorksWithInvalidToken() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.ACCESS_TOKEN.name())
            .param(TOKEN_PARAM, INVALID_TOKEN_VALUE))
      .andExpect(status().isBadRequest());

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.ACCESS_TOKEN.name())
        .param(TOKEN_PARAM, INVALID_TOKEN_VALUE))
      .andExpect(status().isOk());
  }

  @Test
  public void testRevokeAccessTokenIsForbiddenForNonIssuerClients() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.ACCESS_TOKEN.name())
            .param(TOKEN_PARAM, accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));


    mvc
      .perform(post(REVOCATION_ENDPOINT)
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.ACCESS_TOKEN.name())
        .param(TOKEN_PARAM, accessToken))
      .andExpect(status().isForbidden());
  }

  @Test
  public void testRevokeRefreshTokenWorks() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.REFRESH_TOKEN.name())
            .param(TOKEN_PARAM, refreshToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));


    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.REFRESH_TOKEN.name())
        .param(TOKEN_PARAM, refreshToken))
      .andExpect(status().isOk());

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.REFRESH_TOKEN.name())
            .param(TOKEN_PARAM, refreshToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
  }

  @Test
  public void testRevokeRefreshTokenWorksWithInvalidToken() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.REFRESH_TOKEN.name())
            .param(TOKEN_PARAM, INVALID_TOKEN_VALUE))
      .andExpect(status().isBadRequest());

    mvc
      .perform(post(REVOCATION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.REFRESH_TOKEN.name())
        .param(TOKEN_PARAM, INVALID_TOKEN_VALUE))
      .andExpect(status().isOk());
  }

  @Test
  public void testRevokeRefreshTokenIsForbiddenForNonIssuerClients() throws Exception {

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.REFRESH_TOKEN.name())
            .param(TOKEN_PARAM, refreshToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));


    mvc
      .perform(post(REVOCATION_ENDPOINT)
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param(TOKEN_TYPE_HINT_PARAM, TokenTypeHint.REFRESH_TOKEN.name())
        .param(TOKEN_PARAM, refreshToken))
      .andExpect(status().isForbidden());
  }
}
