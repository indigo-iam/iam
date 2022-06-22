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
package it.infn.mw.iam.test.oauth.scope;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.SystemScopeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(
    properties = {"scope.matchers[0].name=storage.read", "scope.matchers[0].type=path",
        "scope.matchers[0].prefix=storage.read", "scope.matchers[0].path=/",
        "scope.matchers[1].name=storage.write", "scope.matchers[1].type=path",
        "scope.matchers[1].prefix=storage.write", "scope.matchers[1].path=/"})
public class StructuredScopeRequestIntegrationTests extends EndpointsTestUtils
    implements StructuredScopeTestSupportConstants {

  @Autowired
  SystemScopeService scopeService;

  @Autowired
  private ObjectMapper mapper;

  @Before
  public void setup() throws Exception {
    SystemScope storageReadScope = new SystemScope("storage.read:/");
    storageReadScope.setRestricted(true);

    SystemScope storageWriteScope = new SystemScope("storage.write:/");
    storageWriteScope.setRestricted(true);

    scopeService.save(storageReadScope);
    scopeService.save(storageWriteScope);
  }

  @Test
  public void test() throws Exception {

    // @formatter:off
    mvc.perform(post("/token")
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("scope", "storage.read:/a-path storage.write:/another-path"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("storage.read:/a-path")))
      .andExpect(jsonPath("$.scope", containsString("storage.write:/another-path")));
    // @formatter:on
  }


  @Test
  public void testIntrospectionResponse() throws Exception {
 // @formatter:off
    String tokenResponse = 
        mvc.perform(post("/token")
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("scope", "storage.read:/a-path storage.write:/another-path"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("storage.read:/a-path")))
      .andExpect(jsonPath("$.scope", containsString("storage.write:/another-path")))
      .andReturn()
      .getResponse().getContentAsString();
    // @formatter:on

    DefaultOAuth2AccessToken tokenResponseObject =
        mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

    String accessToken = tokenResponseObject.getValue();
    mvc
      .perform(post("/introspect")
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("storage.read:/a-path")))
      .andExpect(jsonPath("$.scope", containsString("storage.write:/another-path")));
  }

  @Test
  public void testDeviceCodeStructuredScopeRequest() throws Exception {
    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access storage.read:/test"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);

    String userCode = responseJson.get("user_code").asText();
    String deviceCode = responseJson.get("device_code").asText();

    mvc
      .perform(
          post(TOKEN_ENDPOINT).with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
            .param("grant_type", DEVICE_CODE_GRANT_TYPE)
            .param("device_code", deviceCode))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("authorization_pending")))
      .andExpect(jsonPath("$.error_description",
          equalTo("Authorization pending for code: " + deviceCode)));

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

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();


    String tokenResponse = mvc
      .perform(
          post(TOKEN_ENDPOINT).with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
            .param("grant_type", DEVICE_CODE_GRANT_TYPE)
            .param("device_code", deviceCode))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.refresh_token").exists())
      .andExpect(jsonPath("$.id_token").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", containsString("openid")))
      .andExpect(jsonPath("$.scope", containsString("profile")))
      .andExpect(jsonPath("$.scope", containsString("offline_access")))
      .andExpect(jsonPath("$.scope", containsString("storage.read:/test")))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);

    String accessToken = tokenResponseJson.get("access_token").asText();

    String authorizationHeader = String.format("Bearer %s", accessToken);

    // Check that the token can be used for userinfo and introspection
    mvc.perform(get(USERINFO_ENDPOINT).header("Authorization", authorizationHeader))
      .andExpect(status().isOk());

    mvc
      .perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
  }

  @Test
  public void testRefreshTokenStructuredScopeRequest() throws Exception {

    DefaultOAuth2AccessToken tokenResponse = new AccessTokenGetter().grantType(PASSWORD_GRANT_TYPE)
        .clientId(PASSWORD_CLIENT_ID)
        .clientSecret(PASSWORD_CLIENT_SECRET)
        .username(TEST_USERNAME)
        .password(TEST_PASSWORD)
        .scope("openid storage.read:/ offline_access")
      .getTokenResponseObject();

    assertThat(tokenResponse.getScope(), hasItem("storage.read:/"));

    mvc
      .perform(post("/token").with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .param("grant_type", "refresh_token")
        .param("scope", "openid storage.read:/test offline_access")
        .param("refresh_token", tokenResponse.getRefreshToken().getValue()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.refresh_token").exists())
      .andExpect(jsonPath("$.scope",
          allOf(containsString("storage.read:/test "), containsString("offline_access"),
              containsString("openid"))));

  }
}
