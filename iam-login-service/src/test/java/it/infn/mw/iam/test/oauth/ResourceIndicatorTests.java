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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
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
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class ResourceIndicatorTests implements StructuredScopeTestSupportConstants {

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
      .andExpect(view().name("iam/approveDevice"))
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

  private String getAccessTokenWithRTAfterPasswordFlow(String resourceParamPasswordFlow,
      String resourceParamRTFlow, String resourceValuePasswordFlow, String resourceValueRTFlow)
      throws Exception {
    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile offline_access")
        .param(resourceParamPasswordFlow, resourceValuePasswordFlow))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponseJson).get("refresh_token").asText();

    tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
        .param("refresh_token", refreshToken)
        .param(resourceParamRTFlow, resourceValueRTFlow))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    return mapper.readTree(tokenResponseJson).get("access_token").asText();
  }

  @Test
  public void testResourceIndicatorRequestPasswordFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
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
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
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
    assertThat(claims.getAudience(), hasSize(2));
    assertThat(claims.getAudience(), hasItem("https://example1.org"));
    assertThat(claims.getAudience(), hasItem("https://example2.org"));
  }

  @Test
  public void testResourceIndicatorOverridesAudienceRequestPasswordFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
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
    assertThat(claims.getAudience(), hasSize(2));
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
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
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
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
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
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
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
  public void testEmptyResourceIndicatorValidationFailsPasswordFlow() throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile")
        .param("resource", ""))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value("Not a valid URI: "));

  }

  @Test
  public void testResourceIndicatorWithQueryParameterValidationFailsPasswordFlow()
      throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile")
        .param("resource", "http://example.org?query=true"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description")
        .value("The resource indicator contains a query component: http://example.org?query=true"));

  }

  @Test
  public void testResourceIndicatorWithFragmentValidationFailsPasswordFlow() throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile")
        .param("resource", "http://example.org#fragment"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value(
          "The resource indicator contains a fragment component: http://example.org#fragment"));

  }

  @Test
  public void testResourceIndicatorRequestClientCredentialsFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CREDENTIALS_CLIENT_ID)
        .param("client_secret", CLIENT_CREDENTIALS_CLIENT_SECRET)
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
        .param("client_id", CLIENT_CREDENTIALS_CLIENT_ID)
        .param("client_secret", CLIENT_CREDENTIALS_CLIENT_SECRET)
        .param("resource", "https://example1.org https://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience(), hasSize(2));
    assertThat(claims.getAudience(), hasItem("https://example1.org"));
    assertThat(claims.getAudience(), hasItem("https://example2.org"));
  }

  @Test
  public void testResourceIndicatorOverridesAudienceRequestClientCredentialFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CREDENTIALS_CLIENT_ID)
        .param("client_secret", CLIENT_CREDENTIALS_CLIENT_SECRET)
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
    assertThat(claims.getAudience(), hasSize(2));
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
        .param("client_id", CLIENT_CREDENTIALS_CLIENT_ID)
        .param("client_secret", CLIENT_CREDENTIALS_CLIENT_SECRET)
        .param("resource", "resource"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value("Not a valid URI: resource"));

  }

  @Test
  public void testMultipleResourceIndicatorValidationFailsClientCredentialFlow() throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CREDENTIALS_CLIENT_ID)
        .param("client_secret", CLIENT_CREDENTIALS_CLIENT_SECRET)
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
        .param("client_id", CLIENT_CREDENTIALS_CLIENT_ID)
        .param("client_secret", CLIENT_CREDENTIALS_CLIENT_SECRET)
        .param("resource", "http://example.org resource")
        .param("audience", "aud1 aud2 aud3"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value("Not a valid URI: resource"));

  }

  @Test
  public void testEmptyResourceIndicatorValidationFailsClientCredentialFlow() throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CREDENTIALS_CLIENT_ID)
        .param("client_secret", CLIENT_CREDENTIALS_CLIENT_SECRET)
        .param("resource", ""))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value("Not a valid URI: "));

  }

  @Test
  public void testResourceIndicatorWithQueryParameterValidationFailsClientCredentialsFlow()
      throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CREDENTIALS_CLIENT_ID)
        .param("client_secret", CLIENT_CREDENTIALS_CLIENT_SECRET)
        .param("resource", "http://example.org?query=true"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description")
        .value("The resource indicator contains a query component: http://example.org?query=true"));

  }

  @Test
  public void testResourceIndicatorWithFragmentValidationFailsClientCredentialsFlow()
      throws Exception {

    mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CREDENTIALS_CLIENT_ID)
        .param("client_secret", CLIENT_CREDENTIALS_CLIENT_SECRET)
        .param("resource", "http://example.org#fragment"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value(
          "The resource indicator contains a fragment component: http://example.org#fragment"));

  }

  @Test
  public void testResourceIndicatorRequestRefreshTokenFlow() throws Exception {

    String resource = "https://example.org";

    String accessToken = getAccessTokenWithRTAfterPasswordFlow("resource", "resource", resource, resource);

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), hasItem(resource));

  }

  @Test
  public void testMultipleResourceIndicatorRequestRefreshTokenFlow() throws Exception {

    String resource = "https://example1.org https://example2.org";

    String accessToken = getAccessTokenWithRTAfterPasswordFlow("resource", "resource", resource, resource);

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience(), hasSize(2));
    assertThat(claims.getAudience(), hasItem("https://example1.org"));
    assertThat(claims.getAudience(), hasItem("https://example2.org"));

  }

  @Test
  public void testNarrowerResourceIndicatorRequestRefreshTokenFlow() throws Exception {

    String accessToken = getAccessTokenWithRTAfterPasswordFlow("resource", "resource",
        "https://example1.org https://example2.org", "https://example2.org");

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience(), hasSize(1));
    assertThat(claims.getAudience(), hasItem("https://example2.org"));
  }

  @Test
  public void testFilteredResourceIndicatorRequestRefreshTokenFlow() throws Exception {

    String accessToken = getAccessTokenWithRTAfterPasswordFlow("resource", "resource",
        "https://storm.org https://dcache.org", "https://storm.org https://rucio.org");

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience(), hasSize(1));
    assertThat(claims.getAudience(), hasItem("https://storm.org"));
  }

  @Test
  public void testFilteredResourceIndicatorWithAudRequestRefreshTokenFlow() throws Exception {

    String accessToken = getAccessTokenWithRTAfterPasswordFlow("resource", "audience",
        "https://1.org https://2.org", "https://1.org https://3.org");

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience(), hasSize(1));
    assertThat(claims.getAudience(), hasItem("https://1.org"));
  }

  @Test
  public void testResourceIndicatorNotOriginallyGrantedRTAfterPasswordFlow() throws Exception {
    
    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile offline_access")
        .param("resource", "https://example1.org https://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponseJson).get("refresh_token").asText();

    mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
        .param("refresh_token", refreshToken)
        .param("resource", "https://example3.org"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description")
        .value("The requested resource was not originally granted"));

  }

  @Test
  public void testEmptyResourceIndicatorRequestRTFlowAfterPassword() throws Exception {
    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
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
        .param("client_id", PASSWORD_CLIENT_ID)
        .param("client_secret", PASSWORD_CLIENT_SECRET)
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience(), hasSize(2));
    assertThat(claims.getAudience(), hasItem("https://example1.org"));
    assertThat(claims.getAudience(), hasItem("https://example2.org"));
  }

  @Test
  public void testResourceIndicatorRequestDevideCodeFlow() throws Exception {
    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile")
        .param("resource", "http://example.org"))
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

  }

  @Test
  public void testResourceIndicatorRequestWrongDevideCodeFlow() throws Exception {
    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile")
        .param("resource", "http://example.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();

    approveDeviceCode(userCode);

    mvc
      .perform(
          post(TOKEN_ENDPOINT).with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
            .param("grant_type", DEVICE_CODE_GRANT_TYPE)
            .param("device_code", "1234")
            .param("resource", "http://example.org"))
      .andExpect(status().isBadRequest());

  }

  @Test
  public void testMultipleResourceIndicatorRequestDevideCodeFlow() throws Exception {
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
            .param("resource", "http://example1.org http://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);

    String accessToken = tokenResponseJson.get("access_token").asText();
    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience(), hasSize(2));
    assertThat(claims.getAudience(), hasItem("http://example1.org"));
    assertThat(claims.getAudience(), hasItem("http://example2.org"));

  }

  @Test
  public void testEmptyResourceIndicatorTokenRequestDevideCodeFlow() throws Exception {
    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile")
        .param("resource", "http://example.org"))
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
            .param("device_code", deviceCode))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);

    String accessToken = tokenResponseJson.get("access_token").asText();
    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), contains("http://example.org"));

  }

  @Test
  public void testEmptyResourceIndicatorDeviceCodeRequest() throws Exception {
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

    mvc
      .perform(
          post(TOKEN_ENDPOINT).with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
            .param("grant_type", DEVICE_CODE_GRANT_TYPE)
            .param("device_code", deviceCode)
            .param("resource", "http://example.org"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description")
        .value("The requested resource was not originally granted"));

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
  public void testFilteredResourceIndicatorRequestDevideCodeFlow() throws Exception {
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
            .param("resource", "http://example1.org http://example3.com"))
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
    assertThat(claims.getAudience(), contains("http://example1.org"));

  }

  @Test
  public void testFilteredResourceIndicatorWithAudRequestDevideCodeFlow() throws Exception {
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
            .param("audience", "http://example1.org http://example3.com"))
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
    assertThat(claims.getAudience(), contains("http://example1.org"));

  }

  @Test
  public void testResourceIndicatorNotOriginallyGrantedDevideCodeFlow() throws Exception {
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

    mvc
      .perform(
          post(TOKEN_ENDPOINT).with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
            .param("grant_type", DEVICE_CODE_GRANT_TYPE)
            .param("device_code", deviceCode)
            .param("resource", "http://example3.org"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description")
        .value("The requested resource was not originally granted"));

  }

  @Test
  public void testEmptyResourceIndicatorRequestRTFlowAfterDevideCode() throws Exception {
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

    tokenResponseJson = mapper.readTree(tokenResponse);
    String accessToken = tokenResponseJson.get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertThat(claims.getAudience(), hasSize(2));
    assertThat(claims.getAudience(), hasItem("http://example1.org"));
    assertThat(claims.getAudience(), hasItem("http://example2.org"));

  }

  @Test
  public void testResourceIndicatorNotOriginallyGrantedRTAfterDeviceFlow() throws Exception {
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

    String refreshToken = mapper.readTree(tokenResponse).get("refresh_token").asText();

    mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", DEVICE_CODE_CLIENT_ID)
        .param("client_secret", DEVICE_CODE_CLIENT_SECRET)
        .param("refresh_token", refreshToken)
        .param("resource", "https://example3.org"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description")
        .value("The requested resource was not originally granted"));

  }

  @Test
  public void testResourceIndicatorRTBoundToDeviceRequestParameters() throws Exception {
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
            .param("device_code", deviceCode))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponse).get("refresh_token").asText();

    tokenResponse = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", DEVICE_CODE_CLIENT_ID)
        .param("client_secret", DEVICE_CODE_CLIENT_SECRET)
        .param("refresh_token", refreshToken)
        .param("resource", "http://example1.org http://example2.org"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    responseJson = mapper.readTree(tokenResponse);
    String accessToken = responseJson.get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertThat(claims.getAudience(), hasSize(2));
    assertThat(claims.getAudience(), hasItem("http://example1.org"));
    assertThat(claims.getAudience(), hasItem("http://example2.org"));

  }

  @Test
  public void testAuthzCodeEmptyTokenRequestResourceIndicator() throws Exception {

    MockHttpSession session = (MockHttpSession) mvc
      .perform(get("http://localhost:8080/authorize").contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic("client", TEST_CLIENT_SECRET))
        .queryParam("response_type", "code")
        .queryParam("client_id", TEST_CLIENT_ID)
        .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .queryParam("scope", "openid profile offline_access")
        .queryParam("resource", "http://example1.org http://example2.org")
        .queryParam("nonce", "1")
        .queryParam("state", "1"))
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
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(get("http://localhost:8080/authorize").contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic("client", TEST_CLIENT_SECRET))
        .queryParam("response_type", "code")
        .queryParam("client_id", TEST_CLIENT_ID)
        .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .queryParam("scope", "openid profile offline_access")
        .queryParam("resource", "http://example1.org http://example2.org")
        .queryParam("nonce", "1")
        .queryParam("state", "1")
        .session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    String authzCodeResponse = mvc
      .perform(post("http://localhost:8080/authorize").param("user_oauth_approval", "true")
        .param("authorize", "Authorize")
        .param("remember", "none")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andReturn()
      .getResponse()
      .getHeader("Location");

    String authzCode = UriComponentsBuilder.fromHttpUrl(authzCodeResponse)
      .build()
      .getQueryParams()
      .get("code")
      .get(0);

    String tokenResponse = mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(TEST_CLIENT_ID, TEST_CLIENT_SECRET))
        .param("grant_type", "authorization_code")
        .param("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .param("code", authzCode)
        .param("state", "1"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);
    String accessToken = tokenResponseJson.get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience(), hasSize(2));
    assertThat(claims.getAudience(), hasItem("http://example1.org"));
    assertThat(claims.getAudience(), hasItem("http://example2.org"));
  }

  @Test
  public void testAuthzCodeEmptyAuthzRequestResourceIndicator() throws Exception {

    MockHttpSession session = (MockHttpSession) mvc
      .perform(get("http://localhost:8080/authorize").contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic("client", TEST_CLIENT_SECRET))
        .queryParam("response_type", "code")
        .queryParam("client_id", TEST_CLIENT_ID)
        .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .queryParam("scope", "openid profile offline_access")
        .queryParam("nonce", "1")
        .queryParam("state", "1"))
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
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(get("http://localhost:8080/authorize").contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic("client", TEST_CLIENT_SECRET))
        .queryParam("response_type", "code")
        .queryParam("client_id", TEST_CLIENT_ID)
        .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .queryParam("scope", "openid profile offline_access")
        .queryParam("nonce", "1")
        .queryParam("state", "1")
        .session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    String authzCodeResponse = mvc
      .perform(post("http://localhost:8080/authorize").param("user_oauth_approval", "true")
        .param("authorize", "Authorize")
        .param("remember", "none")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andReturn()
      .getResponse()
      .getHeader("Location");

    String authzCode = UriComponentsBuilder.fromHttpUrl(authzCodeResponse)
      .build()
      .getQueryParams()
      .get("code")
      .get(0);

    mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(TEST_CLIENT_ID, TEST_CLIENT_SECRET))
        .param("grant_type", "authorization_code")
        .param("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .param("code", authzCode)
        .param("state", "1")
        .param("resource", "http://example1.org http://example2.org"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description")
        .value("The requested resource was not originally granted"));

  }

}
