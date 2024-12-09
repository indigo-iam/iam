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
package it.infn.mw.iam.test.oauth;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.test.oauth.devicecode.DeviceCodeTestsConstants;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class ResourceIndicatorTests implements DeviceCodeTestsConstants {

  public static final String TEST_USERNAME = "test";
  public static final String TEST_PASSWORD = "password";

  public static final String PASSWORD_GRANT_CLIENT_ID = "password-grant";
  public static final String PASSWORD_GRANT_CLIENT_SECRET = "secret";

  public static final String CLIENT_CRED_GRANT_CLIENT_ID = "client-cred";
  public static final String CLIENT_CRED_GRANT_CLIENT_SECRET = "secret";

  public static final String TEST_CLIENT_ID = "client";
  public static final String TEST_CLIENT_SECRET = "secret";
  public static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  public static final String LOGIN_URL = "http://localhost/login";
  public static final String AUTHORIZE_URL = "http://localhost/authorize";


  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private MockMvc mvc;

  private void approveDeviceCode(String userCode) throws Exception {
    MockHttpSession session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(DEVICE_USER_URL))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("requestUserCode"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"));
  }

  @Test
  public void testResourceIndicatorRequestPasswordFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile")
        .param("resource", "https://example.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), contains("https://example.org"));
  }

  @Test
  public void testMultipleResourceIndicatorRequestPasswordFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile")
        .param("resource", "https://example1.org https://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(2));
    assertThat(claims.getAudience(), hasItem("https://example1.org"));
    assertThat(claims.getAudience(), hasItem("https://example2.org"));
  }

  @Test
  public void testResourceIndicatorOverridesAudienceRequestPasswordFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile")
        .param("resource", "https://example1.org https://example2.org")
        .param("audience", "aud1 aud2 aud3"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(2));
    assertThat(claims.getAudience(), hasItem("https://example1.org"));
    assertThat(claims.getAudience(), hasItem("https://example2.org"));
    assertThat(claims.getAudience(), not(hasItem("aud1")));
    assertThat(claims.getAudience(), not(hasItem("aud2")));
    assertThat(claims.getAudience(), not(hasItem("aud3")));
  }

  @Test
  public void testResourceIndicatorValidationFailsPasswordFlow() throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile")
        .param("resource", "resource"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value("Not a valid URI: resource"));

  }

  @Test
  public void testMultipleResourceIndicatorValidationFailsPasswordFlow() throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile")
        .param("resource", "http://example.org resource"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value("Not a valid URI: resource"));

  }

  @Test
  public void testResourceIndicatorWithAudienceValidationFailsPasswordFlow() throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile")
        .param("resource", "http://example.org resource")
        .param("audience", "aud1 aud2 aud3"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value("Not a valid URI: resource"));

  }

  @Test
  public void testResourceIndicatorRequestClientCredentialsFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
        .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
        .param("resource", "https://example.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();
    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), contains("https://example.org"));
  }

  @Test
  public void testMultipleResourceIndicatorClientCredentialFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
        .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
        .param("resource", "https://example1.org https://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(2));
    assertThat(claims.getAudience(), hasItem("https://example1.org"));
    assertThat(claims.getAudience(), hasItem("https://example2.org"));
  }

  @Test
  public void testResourceIndicatorOverridesAudienceRequestClientCredentialFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
        .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
        .param("resource", "https://example1.org https://example2.org")
        .param("audience", "aud1 aud2 aud3"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(2));
    assertThat(claims.getAudience(), hasItem("https://example1.org"));
    assertThat(claims.getAudience(), hasItem("https://example2.org"));
    assertThat(claims.getAudience(), not(hasItem("aud1")));
    assertThat(claims.getAudience(), not(hasItem("aud2")));
    assertThat(claims.getAudience(), not(hasItem("aud3")));
  }

  @Test
  public void testResourceIndicatorValidationFailsClientCredentialFlow() throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
        .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
        .param("resource", "resource"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value("Not a valid URI: resource"));

  }

  @Test
  public void testMultipleResourceIndicatorValidationFailsClientCredentialFlow() throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
        .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
        .param("resource", "http://example.org resource"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value("Not a valid URI: resource"));

  }

  @Test
  public void testResourceIndicatorWithAudienceValidationFailsClientCredentialFlow()
      throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
        .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
        .param("resource", "http://example.org resource")
        .param("audience", "aud1 aud2 aud3"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value("Not a valid URI: resource"));

  }

  @Test
  public void testResourceIndicatorRequestRefreshTokenFlow() throws Exception {
    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile offline_access"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponseJson).get("refresh_token").asText();

    tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("refresh_token", refreshToken)
        .param("resource", "https://example.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), hasItem("https://example.org"));

    tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    token = JWTParser.parse(accessToken);
    claims = token.getJWTClaimsSet();

    assertThat(claims.getAudience(), empty());
  }

  @Test
  public void testNarrowerResourceIndicatorRequestRefreshTokenFlow() throws Exception {
    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile offline_access")
        .param("resource", "https://example1.org https://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponseJson).get("refresh_token").asText();

    tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("refresh_token", refreshToken)
        .param("resource", "https://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), hasItem("https://example2.org"));
  }

  @Test
  public void testDefaultResourceIndicatorRequestRefreshTokenFlow() throws Exception {
    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile offline_access")
        .param("resource", "https://example1.org https://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponseJson).get("refresh_token").asText();

    tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(2));
    assertThat(claims.getAudience(), hasItem("https://example1.org"));
    assertThat(claims.getAudience(), hasItem("https://example2.org"));
  }

  @Test
  public void testResourceIndicatorRequestDevideCodeFlow() throws Exception {
    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();
    String deviceCode = responseJson.get("device_code").asText();

    approveDeviceCode(userCode);

    String tokenResponse = mvc
      .perform(
          post(TOKEN_ENDPOINT).with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
            .param("grant_type", DEVICE_CODE_GRANT_TYPE)
            .param("device_code", deviceCode)
            .param("resource", "http://example.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);

    String accessToken = tokenResponseJson.get("access_token").asText();
    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), contains("http://example.org"));

    response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    responseJson = mapper.readTree(response);
    userCode = responseJson.get("user_code").asText();
    deviceCode = responseJson.get("device_code").asText();

    approveDeviceCode(userCode);

    tokenResponse = mvc
      .perform(
          post(TOKEN_ENDPOINT).with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
            .param("grant_type", DEVICE_CODE_GRANT_TYPE)
            .param("device_code", deviceCode))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    tokenResponseJson = mapper.readTree(tokenResponse);

    accessToken = tokenResponseJson.get("access_token").asText();
    token = JWTParser.parse(accessToken);
    claims = token.getJWTClaimsSet();

    assertThat(claims.getAudience(), empty());
  }

  @Test
  public void testNarrowerResourceIndicatorRequestDevideCodeFlow() throws Exception {
    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile")
        .param("resource", "http://example1.org http://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();
    String deviceCode = responseJson.get("device_code").asText();

    approveDeviceCode(userCode);

    String tokenResponse = mvc
      .perform(
          post(TOKEN_ENDPOINT).with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
            .param("grant_type", DEVICE_CODE_GRANT_TYPE)
            .param("device_code", deviceCode)
            .param("resource", "http://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);

    String accessToken = tokenResponseJson.get("access_token").asText();
    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), contains("http://example2.org"));

  }

  @Test
  public void testDefaultResourceIndicatorRequestDevideCodeFlow() throws Exception {
    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access")
        .param("resource", "http://example1.org http://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();
    String deviceCode = responseJson.get("device_code").asText();

    approveDeviceCode(userCode);

    String tokenResponse = mvc
      .perform(
          post(TOKEN_ENDPOINT).with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
            .param("grant_type", DEVICE_CODE_GRANT_TYPE)
            .param("device_code", deviceCode)
            .param("resource", "http://example1.org http://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);

    String refreshToken = tokenResponseJson.get("refresh_token").asText();

    tokenResponse = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", DEVICE_CODE_CLIENT_ID)
        .param("client_secret", DEVICE_CODE_CLIENT_SECRET)
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponse).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(2));
    assertThat(claims.getAudience(), hasItem("http://example1.org"));
    assertThat(claims.getAudience(), hasItem("http://example2.org"));

  }

}
