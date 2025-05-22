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
package it.infn.mw.iam.test.oauth.scope.pdp.wlcg;

import static it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy.PATH;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
//import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@TestPropertySource(properties = {"iam.access_token.include_scope=true"})
@IamMockMvcIntegrationTest
@ActiveProfiles({"h2-test", "h2", "wlcg-scopes"})
public class OtherFlowsIntegrationTests extends ScopePolicyTestUtils {

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamScopePolicyRepository scopePolicyRepo;

  @Autowired
  private MockMvc mvc;

  @Autowired
  protected ObjectMapper mapper;

  public static final String LOCALHOST_URL_TEMPLATE = "http://localhost:%d";

  IamAccount findTestAccount() {
    return accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found!"));
  }

  private MvcResult passwordFlow(String clientId, String clientSecret, String username,
      String password, String scopes) throws Exception {

    return mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", clientId)
        .param("client_secret", clientSecret)
        .param("username", username)
        .param("password", password)
        .param("scope", scopes))
      .andExpect(status().isOk())
      .andReturn();
  }

  private MvcResult refreshFlow(String clientId, String clientSecret, String refreshToken)
      throws Exception {
    return mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", clientId)
        .param("client_secret", clientSecret)
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk())
      .andReturn();
  }

  private MvcResult refreshFlow(String clientId, String clientSecret, String refreshToken,
      String scopes) throws Exception {
    return mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", clientId)
        .param("client_secret", clientSecret)
        .param("refresh_token", refreshToken)
        .param("scope", scopes))
      .andExpect(status().isOk())
      .andReturn();
  }

  private void checkAccessTokenScopes(String accessToken, Set<String> scopes) throws ParseException {

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();
    List<String> tokenScopes = Arrays.asList(claims.getStringClaim("scope").split(" "));
    assertTrue(tokenScopes.size() == scopes.size());
    assertTrue(tokenScopes.containsAll(scopes));
  }

  @Test
  public void testRefreshTokenAfterPasswordFlowParametricScopeFilteringWorks() throws Exception {

    final String CLIENT_ID = "password-grant";
    final String CLIENT_SECRET = "secret";
    final String ALL_SCOPES = "openid profile offline_access storage.read:/ storage.modify:/";

    IamAccount testAccount = findTestAccount();

    IamScopePolicy up = initDenyScopePolicy();
    up.setAccount(testAccount);
    up.setScopes(Sets.newHashSet("storage.read:/", "storage.modify:/"));
    up.setMatchingPolicy(PATH);

    scopePolicyRepo.save(up);

    String response =
        passwordFlow(CLIENT_ID, CLIENT_SECRET, "test", "password", ALL_SCOPES).getResponse()
          .getContentAsString();

    String refreshToken = mapper.readTree(response).get("refresh_token").asText();
    String accessToken = mapper.readTree(response).get("access_token").asText();

    accessToken = mapper
      .readTree(
          refreshFlow(CLIENT_ID, CLIENT_SECRET, refreshToken).getResponse().getContentAsString())
      .get("access_token")
      .asText();

    checkAccessTokenScopes(accessToken, Set.of("openid", "profile", "offline_access"));

    accessToken = mapper
        .readTree(
            refreshFlow(CLIENT_ID, CLIENT_SECRET, refreshToken, "openid profile").getResponse().getContentAsString())
        .get("access_token")
        .asText();

    checkAccessTokenScopes(accessToken, Set.of("openid", "profile"));

    scopePolicyRepo.delete(up);
  }


  @Test
  public void testRefreshTokenAfterDeviceFlowWithParametricScopeRequestWorks() throws Exception {

    IamAccount testAccount = findTestAccount();

    IamScopePolicy denyAllPolicy = initDenyScopePolicy();
    denyAllPolicy.setScopes(Sets.newHashSet("storage.read:/", "storage.write:/"));
    denyAllPolicy.setMatchingPolicy(PATH);
    scopePolicyRepo.save(denyAllPolicy);

    IamScopePolicy allowUserWithPathPolicy = initPermitScopePolicy();
    allowUserWithPathPolicy.setAccount(testAccount);
    allowUserWithPathPolicy.setScopes(Sets.newHashSet("storage.read:/path", "storage.write:/path"));
    allowUserWithPathPolicy.setMatchingPolicy(PATH);
    scopePolicyRepo.save(allowUserWithPathPolicy);

    String response = mvc
      .perform(post("/devicecode").contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic("refresh-client", "secret"))
        .param("client_id", "refresh-client")
        .param("scope", "openid profile offline_access storage.read:/ storage.read:/path"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();
    String deviceCode = responseJson.get("device_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get("/device"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/login").param("username", "test")
        .param("password", "password")
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/device"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/device/verify").param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/device/approve").param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    String tokenResponse = mvc
      .perform(post("/token").with(httpBasic("refresh-client", "secret"))
        .param("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
        .param("device_code", deviceCode))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.refresh_token").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", containsString("openid")))
      .andExpect(jsonPath("$.scope", containsString("profile")))
      .andExpect(jsonPath("$.scope", containsString("offline_access")))
      .andExpect(jsonPath("$.scope", containsString("storage.read:/path")))
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponse).get("refresh_token").asText();

    tokenResponse = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", "refresh-client")
        .param("client_secret", "secret")
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponse).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertTrue(claims.getStringClaim("scope").contains("openid"));
    assertTrue(claims.getStringClaim("scope").contains("profile"));
    assertTrue(claims.getStringClaim("scope").contains("offline_access"));
    assertTrue(claims.getStringClaim("scope").contains("storage.read:/path"));

    mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", "refresh-client")
        .param("client_secret", "secret")
        .param("refresh_token", refreshToken)
        .param("scope", "openid profile offline_access storage.read:/another storage.read:/path"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error_description", equalTo("Up-scoping is not allowed.")));

    mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", "refresh-client")
        .param("client_secret", "secret")
        .param("refresh_token", refreshToken)
        .param("scope", "openid profile offline_access storage.read:/ storage.read:/path"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error_description", equalTo("Up-scoping is not allowed.")));

    scopePolicyRepo.delete(denyAllPolicy);
    scopePolicyRepo.delete(allowUserWithPathPolicy);
  }

  @Test
  public void testRefreshTokenFlowAfterDevicePolicyWithPathWorks() throws Exception {

    IamAccount testAccount = findTestAccount();

    IamScopePolicy denyAllPolicy = initDenyScopePolicy();
    denyAllPolicy.setScopes(Sets.newHashSet("storage.read:/", "storage.write:/"));
    denyAllPolicy.setMatchingPolicy(PATH);
    scopePolicyRepo.save(denyAllPolicy);

    IamScopePolicy allowUserWithPathPolicy = initPermitScopePolicy();
    allowUserWithPathPolicy.setAccount(testAccount);
    allowUserWithPathPolicy.setScopes(Sets.newHashSet("storage.read:/home", "storage.write:/home"));
    allowUserWithPathPolicy.setMatchingPolicy(PATH);
    scopePolicyRepo.save(allowUserWithPathPolicy);

    String response = mvc.perform(post("/devicecode").contentType(APPLICATION_FORM_URLENCODED)
      .with(httpBasic("refresh-client", "secret"))
      .param("client_id", "refresh-client")
      .param("scope",
          "openid profile offline_access storage.read:/ storage.read:/home storage.read:/home/test"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();
    String deviceCode = responseJson.get("device_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get("/device"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/login").param("username", "test")
        .param("password", "password")
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/device"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/device/verify").param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/device/approve").param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    String tokenResponse = mvc
      .perform(post("/token").with(httpBasic("refresh-client", "secret"))
        .param("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
        .param("device_code", deviceCode))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.refresh_token").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponse).get("refresh_token").asText();
    List<String> scopes =
        Arrays.asList(mapper.readTree(tokenResponse).get("scope").asText().split(" "));
    assertTrue(scopes.contains("openid"));
    assertTrue(scopes.contains("openid"));
    assertTrue(scopes.contains("profile"));
    assertTrue(scopes.contains("offline_access"));
    assertFalse(scopes.contains("storage.read:/"));
    assertTrue(scopes.contains("storage.read:/home"));
    assertTrue(scopes.contains("storage.read:/home/test"));

    tokenResponse = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", "refresh-client")
        .param("client_secret", "secret")
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponse).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    scopes = Arrays.asList(claims.getStringClaim("scope").split(" "));
    assertTrue(scopes.contains("openid"));
    assertTrue(scopes.contains("openid"));
    assertTrue(scopes.contains("profile"));
    assertTrue(scopes.contains("offline_access"));
    assertFalse(scopes.contains("storage.read:/"));
    assertTrue(scopes.contains("storage.read:/home"));
    assertTrue(scopes.contains("storage.read:/home/test"));

    mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", "refresh-client")
        .param("client_secret", "secret")
        .param("refresh_token", refreshToken)
        .param("scope", "openid profile offline_access storage.read:/"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error_description", equalTo("Up-scoping is not allowed.")));

    scopePolicyRepo.delete(denyAllPolicy);
    scopePolicyRepo.delete(allowUserWithPathPolicy);
  }

  @Test
  public void testRefreshedTokenWithDeniedPathNotReturned() throws Exception {

    IamAccount testAccount = findTestAccount();

    IamScopePolicy up = initDenyScopePolicy();
    up.setAccount(testAccount);
    up.setScopes(Sets.newHashSet("storage.read:/home"));
    up.setMatchingPolicy(PATH);

    scopePolicyRepo.save(up);

    String response = mvc.perform(post("/devicecode").contentType(APPLICATION_FORM_URLENCODED)
      .with(httpBasic("refresh-client", "secret"))
      .param("client_id", "refresh-client")
      .param("scope",
          "openid profile offline_access storage.read:/ storage.read:/home storage.read:/home/test"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();
    String deviceCode = responseJson.get("device_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get("/device"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/login").param("username", "test")
        .param("password", "password")
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/device"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/device/verify").param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/device/approve").param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    String tokenResponse = mvc
      .perform(post("/token").with(httpBasic("refresh-client", "secret"))
        .param("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
        .param("device_code", deviceCode))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.refresh_token").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", containsString("openid")))
      .andExpect(jsonPath("$.scope", containsString("profile")))
      .andExpect(jsonPath("$.scope", containsString("offline_access")))
      .andExpect(jsonPath("$.scope", containsString("storage.read:/")))
      .andExpect(jsonPath("$.scope", not(containsString("storage.read:/home"))))
      .andExpect(jsonPath("$.scope", not(containsString("storage.read:/home/test"))))
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponse).get("refresh_token").asText();

    tokenResponse = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", "refresh-client")
        .param("client_secret", "secret")
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponse).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertTrue(claims.getStringClaim("scope").contains("openid"));
    assertTrue(claims.getStringClaim("scope").contains("profile"));
    assertTrue(claims.getStringClaim("scope").contains("offline_access"));
    assertTrue(claims.getStringClaim("scope").contains("storage.read:/"));
    assertFalse(claims.getStringClaim("scope").contains("storage.read:/home"));
    assertFalse(claims.getStringClaim("scope").contains("storage.read:/home/test"));

    String responseContent = mvc.perform(post("/token").param("grant_type", "refresh_token")
      .param("client_id", "refresh-client")
      .param("client_secret", "secret")
      .param("refresh_token", refreshToken)
      .param("scope",
          "openid profile offline_access storage.read:/ storage.read:/home storage.read:/home/test"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope").exists())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String scope = JsonPath.read(responseContent, "$.scope");
    List<String> scopes = Arrays.asList(scope.split(" "));
    assertFalse(scopes.contains("storage.read:/home"));
    assertFalse(scopes.contains("storage.read:/home/test"));
    assertTrue(scopes.contains("storage.read:/"));

    scopePolicyRepo.delete(up);
  }

  @Test
  public void testRefreshFlowAfterDeviceCodeWithDenyPolicyOnRootPath() throws Exception {

    IamAccount testAccount = findTestAccount();

    IamScopePolicy up = initDenyScopePolicy();
    up.setAccount(testAccount);
    up.setScopes(Sets.newHashSet("storage.read:/"));
    up.setMatchingPolicy(PATH);

    scopePolicyRepo.save(up);

    String response = mvc
      .perform(post("/devicecode").contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic("device-code-client", "secret"))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access storage.read:/ storage.read:/path"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();
    String deviceCode = responseJson.get("device_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get("/device"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/login").param("username", "test")
        .param("password", "password")
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/device"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/device/verify").param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/device/approve").param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    String tokenResponse = mvc
      .perform(post("/token").with(httpBasic("device-code-client", "secret"))
        .param("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
        .param("device_code", deviceCode))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.refresh_token").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", containsString("openid")))
      .andExpect(jsonPath("$.scope", containsString("profile")))
      .andExpect(jsonPath("$.scope", containsString("offline_access")))
      .andExpect(jsonPath("$.scope", not(containsString("storage.read:/"))))
      .andExpect(jsonPath("$.scope", not(containsString("storage.read:/path"))))
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponse).get("refresh_token").asText();

    tokenResponse = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", "device-code-client")
        .param("client_secret", "secret")
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponse).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertTrue(claims.getStringClaim("scope").contains("openid"));
    assertTrue(claims.getStringClaim("scope").contains("profile"));
    assertTrue(claims.getStringClaim("scope").contains("offline_access"));
    assertFalse(claims.getStringClaim("scope").contains("storage.read:/"));
    assertFalse(claims.getStringClaim("scope").contains("storage.read:/path"));

    mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", "device-code-client")
        .param("client_secret", "secret")
        .param("refresh_token", refreshToken)
        .param("scope", "openid profile offline_access storage.read:/ storage.read:/path"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error_description", equalTo("Up-scoping is not allowed.")));

    scopePolicyRepo.delete(up);

  }

}
