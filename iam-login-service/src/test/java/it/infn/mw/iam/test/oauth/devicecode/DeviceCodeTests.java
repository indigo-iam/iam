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
package it.infn.mw.iam.test.oauth.devicecode;

import static it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.REGISTER_ENDPOINT;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.io.UnsupportedEncodingException;
import java.util.Optional;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.web.ApprovedSiteAPI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class DeviceCodeTests extends EndpointsTestUtils implements DeviceCodeTestsConstants {

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private ObjectMapper objectMapper;

  private String getTokenResponse(String clientId, String clientSecret, String username,
      String password, String scopes) throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(clientId, clientSecret))
        .param("client_id", clientId)
        .param("scope", scopes))
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
      .perform(post(LOGIN_URL).param("username", username)
        .param("password", password)
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

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    return mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(clientId, clientSecret))
        .param("grant_type", DEVICE_CODE_GRANT_TYPE)
        .param("device_code", deviceCode))
      .andReturn()
      .getResponse()
      .getContentAsString();
  }

  @Test
  public void testDeviceCodeEndpointRequiresClientWithDeviceCodeGrantEnabled() throws Exception {

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client"))
      .andExpect(status().isOk());

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic("client", "secret"))
        .param("client_id", "client"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", equalTo("invalid_client")))
      .andExpect(jsonPath("$.error_description",
          equalTo("Unauthorized grant type: " + DEVICE_CODE_GRANT_TYPE)));

  }

  @Test
  public void testDeviceCodeWithoutAllowedScope() throws Exception {

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid not-allowed-scope"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("invalid_scope")))
      .andExpect(jsonPath("$.error_description",
          equalTo("One or more requested scope is not allowed for client 'device-code-client'")));

  }


  @Test
  public void testDeviceCodeNoApproval() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access"))
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
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "false")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();


    response = mvc
        .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
          .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
          .param("client_id", "device-code-client")
          .param("scope", "openid profile offline_access"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.user_code").isString())
        .andExpect(jsonPath("$.device_code").isString())
        .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
        .andReturn()
        .getResponse()
        .getContentAsString();

      responseJson = mapper.readTree(response);

      userCode = responseJson.get("user_code").asText();

      session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL).session(session))
        .andExpect(status().isOk())
        .andExpect(view().name("requestUserCode"))
        .andReturn()
        .getRequest()
        .getSession();

      mvc
        .perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
        .andExpect(status().isOk())
        .andExpect(view().name("iam/approveDevice"));

  }


  @Test
  public void testDevideCodeFlowWithAudience() throws Exception {
    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access"))
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
            .param("device_code", deviceCode)
            .param("aud", "example-audience"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.refresh_token").exists())
      .andExpect(jsonPath("$.id_token").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", containsString("openid")))
      .andExpect(jsonPath("$.scope", containsString("profile")))
      .andExpect(jsonPath("$.scope", containsString("offline_access")))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);

    String accessToken = tokenResponseJson.get("access_token").asText();
    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertTrue(claims.getAudience().size() == 1);
    assertTrue(claims.getAudience().contains("example-audience"));
  }

  @Test
  public void testDeviceCodeApprovalFlowWorks() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access"))
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

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .param("remember", "until-revoked")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get("/" + ApprovedSiteAPI.URL).session(session))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[0].clientId", equalTo(DEVICE_CODE_CLIENT_ID)))
      .andExpect(jsonPath("$[0].userId", equalTo(TEST_USERNAME)));


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
      .andExpect(jsonPath("$.scope", not(containsString("email"))))
      .andExpect(jsonPath("$.scope", not(containsString("phone"))))
      .andExpect(jsonPath("$.scope", not(containsString("address"))))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);

    String accessToken = tokenResponseJson.get("access_token").asText();

    String authorizationHeader = String.format("Bearer %s", accessToken);

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
  public void testDeviceCodeFlowDoesNotWorkIfScopeNotAllowed() throws Exception {

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access custom-scope"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("invalid_scope")));
  }

  @Test
  public void deviceCodeDoesNotWorkForDynamicallyRegisteredClientIfScopeNotAllowed()
      throws UnsupportedEncodingException, Exception {

    String jsonInString = ClientJsonStringBuilder.builder()
      .grantTypes("urn:ietf:params:oauth:grant-type:device_code")
      .scopes("openid", "profile", "offline_access")
      .build();

    String clientJson =
        mvc.perform(post(REGISTER_ENDPOINT).contentType(APPLICATION_JSON).content(jsonInString))
          .andExpect(status().isCreated())
          .andExpect(jsonPath("$.registration_access_token").exists())
          .andExpect(jsonPath("$.registration_client_uri").exists())
          .andExpect(jsonPath("$.scope", containsString("offline_access")))
          .andReturn()
          .getResponse()
          .getContentAsString();

    RegisteredClientDTO registrationResponse =
        objectMapper.readValue(clientJson, RegisteredClientDTO.class);

    ClientDetailsEntity newClient =
        clientRepo.findByClientId(registrationResponse.getClientId()).orElseThrow();

    assertNotNull(newClient);

    RequestPostProcessor clientBasicAuth =
        httpBasic(newClient.getClientId(), newClient.getClientSecret());

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(clientBasicAuth)
        .param("client_id", newClient.getClientId())
        .param("scope", "openid profile offline_access custom-scope"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("invalid_scope")));
  }


  @Test
  public void deviceCodeWorksForDynamicallyRegisteredClient()
      throws UnsupportedEncodingException, Exception {

    String jsonInString = ClientJsonStringBuilder.builder()
      .grantTypes("urn:ietf:params:oauth:grant-type:device_code")
      .scopes("openid", "profile", "offline_access")
      .build();

    String clientJson =
        mvc.perform(post(REGISTER_ENDPOINT).contentType(APPLICATION_JSON).content(jsonInString))
          .andExpect(status().isCreated())
          .andExpect(jsonPath("$.registration_access_token").exists())
          .andExpect(jsonPath("$.registration_client_uri").exists())
          .andExpect(jsonPath("$.scope", containsString("offline_access")))
          .andReturn()
          .getResponse()
          .getContentAsString();

    RegisteredClientDTO registrationResponse =
        objectMapper.readValue(clientJson, RegisteredClientDTO.class);

    ClientDetailsEntity newClient =
        clientRepo.findByClientId(registrationResponse.getClientId()).orElseThrow();

    assertNotNull(newClient);

    String tokenResponse = getTokenResponse(newClient.getClientId(), newClient.getClientSecret(),
        TEST_USERNAME, TEST_PASSWORD, "openid profile offline_access");

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);

    String accessToken = tokenResponseJson.get("access_token").asText();

    String authorizationHeader = String.format("Bearer %s", accessToken);

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
  public void publicClientDeviceCodeWorks() throws Exception {

    Optional<ClientDetailsEntity> client = clientRepo.findByClientId(PUBLIC_DEVICE_CODE_CLIENT_ID);
    Set<String> scopes = Sets.newHashSet();
    scopes.add("openid");
    scopes.add("profile");
    if (client.isPresent()) {
      client.get().setScope(scopes);
    }
    String deviceResponse = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .param("client_id", PUBLIC_DEVICE_CODE_CLIENT_ID)
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andExpect(jsonPath("$.expires_in", is(600)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(deviceResponse);

    String userCode = responseJson.get("user_code").asText();
    String deviceCode = responseJson.get("device_code").asText();

    mvc
      .perform(post(TOKEN_ENDPOINT).param("grant_type", DEVICE_CODE_GRANT_TYPE)
        .param("device_code", deviceCode)
        .param("client_id", PUBLIC_DEVICE_CODE_CLIENT_ID))
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
      .andExpect(view().name("iam/approveDevice"))
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
      .perform(post(TOKEN_ENDPOINT).param("grant_type", DEVICE_CODE_GRANT_TYPE)
        .param("device_code", deviceCode)
        .param("client_id", PUBLIC_DEVICE_CODE_CLIENT_ID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.id_token").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", containsString("openid")))
      .andExpect(jsonPath("$.scope", containsString("profile")))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);

    String accessToken = tokenResponseJson.get("access_token").asText();

    String authorizationHeader = String.format("Bearer %s", accessToken);

    mvc.perform(get(USERINFO_ENDPOINT).header("Authorization", authorizationHeader))
      .andExpect(status().isOk());
  }

  @Test
  public void testRefreshedTokenAfterDeviceCodeApprovalFlowWorks() throws Exception {

    final String SCIM_DEVICE_CLIENT_ID = "scim-client-rw";
    final String SCIM_DEVICE_CLIENT_SECRET = "secret";

    String tokenResponse = getTokenResponse(SCIM_DEVICE_CLIENT_ID, SCIM_DEVICE_CLIENT_SECRET,
        TEST_USERNAME, TEST_PASSWORD, "openid profile offline_access scim:read scim:write");

    JsonNode tokenResponseJson = mapper.readTree(tokenResponse);

    String accessToken = tokenResponseJson.get("access_token").asText();
    String refreshToken = tokenResponseJson.get("refresh_token").asText();

    String authorizationHeader = String.format("Bearer %s", accessToken);

    mvc.perform(get(USERINFO_ENDPOINT).header("Authorization", authorizationHeader))
      .andExpect(status().isOk());

    mvc
      .perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(SCIM_DEVICE_CLIENT_ID, SCIM_DEVICE_CLIENT_SECRET))
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));

    String refreshTokenResponse = mvc
      .perform(
          post(TOKEN_ENDPOINT).with(httpBasic(SCIM_DEVICE_CLIENT_ID, SCIM_DEVICE_CLIENT_SECRET))
            .param("grant_type", "refresh_token")
            .param("refresh_token", refreshToken)
            .param("scope", "openid"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.id_token").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", containsString("openid")))
      .andExpect(jsonPath("$.scope", not(containsString("scim:read"))))
      .andExpect(jsonPath("$.scope", not(containsString("scim:write"))))
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessTokenNoSCIM = mapper.readTree(refreshTokenResponse).get("access_token").asText();

    String scimAuthorizationHeader = String.format("Bearer %s", accessTokenNoSCIM);

    mvc.perform(get("/scim/Users").header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isForbidden());
    mvc.perform(get("/scim/Groups").header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isForbidden());
    mvc
      .perform(get("/scim/Users/80e5fb8d-b7c8-451a-89ba-346ae278a66f").header("Authorization",
          scimAuthorizationHeader))
      .andExpect(status().isForbidden());
    mvc
      .perform(get("/scim/Groups/c617d586-54e6-411d-8e38-649677980001").header("Authorization",
          scimAuthorizationHeader))
      .andExpect(status().isForbidden());
    mvc
      .perform(delete("/scim/Users/80e5fb8d-b7c8-451a-89ba-346ae278a66f").header("Authorization",
          scimAuthorizationHeader))
      .andExpect(status().isForbidden());
    mvc
      .perform(delete("/scim/Groups/c617d586-54e6-411d-8e38-649677980001").header("Authorization",
          scimAuthorizationHeader))
      .andExpect(status().isForbidden());

    refreshTokenResponse = mvc
      .perform(
          post(TOKEN_ENDPOINT).with(httpBasic(SCIM_DEVICE_CLIENT_ID, SCIM_DEVICE_CLIENT_SECRET))
            .param("grant_type", "refresh_token")
            .param("refresh_token", refreshToken)
            .param("scope", "openid scim:read scim:write"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.id_token").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", containsString("openid")))
      .andExpect(jsonPath("$.scope", containsString("scim:read")))
      .andExpect(jsonPath("$.scope", containsString("scim:write")))
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessTokenWithSCIM = mapper.readTree(refreshTokenResponse).get("access_token").asText();

    scimAuthorizationHeader = String.format("Bearer %s", accessTokenWithSCIM);

    mvc.perform(get("/scim/Users").header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isOk());
    mvc.perform(get("/scim/Groups").header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isOk());
    mvc
      .perform(get("/scim/Users/80e5fb8d-b7c8-451a-89ba-346ae278a66f").header("Authorization",
          scimAuthorizationHeader))
      .andExpect(status().isOk());
    mvc
      .perform(get("/scim/Groups/c617d586-54e6-411d-8e38-649677980001").header("Authorization",
          scimAuthorizationHeader))
      .andExpect(status().isOk());

  }

  @Test
  public void testAdminScopesAllowedToAdmins() throws Exception {

    String tokenResponse = getTokenResponse("scim-client-rw", "secret", "admin", "password",
        "offline_access iam:admin.read iam:admin.write");

    assertTrue(tokenResponse.contains("access_token"));
    assertTrue(tokenResponse.contains("offline_access"));
    assertTrue(tokenResponse.contains("iam:admin.read"));
    assertTrue(tokenResponse.contains("iam:admin.write"));
  }

  @Test
  public void testFilteredAdminScopes() throws Exception {

    String tokenResponse = getTokenResponse("scim-client-rw", "secret", "test", "password",
        "offline_access iam:admin.read iam:admin.write");
    assertTrue(tokenResponse.contains("access_token"));
    assertTrue(tokenResponse.contains("offline_access"));
    assertFalse(tokenResponse.contains("iam:admin.read"));
    assertFalse(tokenResponse.contains("iam:admin.write"));
  }

  @Test
  public void testAdminScopesWithRefreshedTokenAllowedToAdmins() throws Exception {

    String tokenResponse = getTokenResponse("scim-client-rw", "secret", "admin", "password",
        "offline_access iam:admin.read iam:admin.write");

    String refreshToken = mapper.readTree(tokenResponse).get("refresh_token").asText();

    mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic("scim-client-rw", "secret"))
        .param("grant_type", "refresh_token")
        .param("refresh_token", refreshToken)
        .param("scope", "iam:admin.read iam:admin.write"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("iam:admin.read")))
      .andExpect(jsonPath("$.scope", containsString("iam:admin.write")));
  }

  @Test
  public void testFilteredAdminScopesWithRefreshedToken() throws Exception {

    String tokenResponse = getTokenResponse("scim-client-rw", "secret", "test", "password",
        "offline_access iam:admin.read iam:admin.write");

    String refreshToken = mapper.readTree(tokenResponse).get("refresh_token").asText();

    mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic("scim-client-rw", "secret"))
        .param("grant_type", "refresh_token")
        .param("refresh_token", refreshToken)
        .param("scope", "iam:admin.read iam:admin.write"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("invalid_scope")))
      .andExpect(jsonPath("$.error_description", equalTo("Up-scoping is not allowed.")));
  }

}
