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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class ResourceIndicatorTests {

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
        .param("scope", "openid profile offline_access")
        .param("resource", "https://example.org"))
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

}
