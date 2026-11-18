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
package it.infn.mw.iam.test.api.account.management;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

/**
 * Tokens are obtained from the token endpoint and sent as bearer tokens, as real clients do.
 */
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class UserManagerTokenFlowTests {

  static final String MANAGER = "test_100";
  static final String USER = "test_102";
  static final String REGULAR_USER = "test_103";
  static final String ADMIN = "admin";

  static final String[] USER_SCOPES = {"iam:user.read", "iam:user.write"};
  static final String[] ADMIN_SCOPES =
      {"iam:admin.read", "iam:admin.write", "scim:read", "scim:write"};
  static final String EVERY_SCOPE = "openid offline_access " + String.join(" ", USER_SCOPES) + " "
      + String.join(" ", ADMIN_SCOPES);

  static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
  static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";

  @Autowired
  MockMvc mvc;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  IamAuthoritiesRepository authoritiesRepo;

  @Autowired
  IamClientRepository clientRepo;

  @BeforeEach
  void setup() {
    setUserManager(MANAGER, true);

    for (String clientId : new String[] {"password-grant", "device-code-client",
        "public-dc-client", "client-cred", "token-exchange-subject", "token-exchange-actor"}) {
      ClientDetailsEntity client = clientRepo.findByClientId(clientId).orElseThrow();
      Set<String> scopes = new HashSet<>(client.getScope());
      scopes.addAll(Arrays.asList(EVERY_SCOPE.split(" ")));
      client.setScope(scopes);
      clientRepo.save(client);
    }
  }

  private String uuid(String username) {
    return accountRepo.findByUsername(username).orElseThrow().getUuid();
  }

  private boolean isActive(String username) {
    return accountRepo.findByUsername(username).orElseThrow().isActive();
  }

  private void setUserManager(String username, boolean userManager) {
    IamAuthority role = authoritiesRepo.findByAuthority("ROLE_USER_MANAGER").orElseThrow();
    IamAccount account = accountRepo.findByUsername(username).orElseThrow();
    if (userManager) {
      account.getAuthorities().add(role);
    } else {
      account.getAuthorities().remove(role);
    }
    accountRepo.save(account);
  }

  private MockHttpServletRequestBuilder tokenRequest(String clientId) {
    return post("/token").param("client_id", clientId).param("client_secret", "secret");
  }

  private JsonNode json(MockHttpServletRequestBuilder request) throws Exception {
    return mapper.readTree(mvc.perform(request)
      .andExpect(status().is2xxSuccessful())
      .andReturn()
      .getResponse()
      .getContentAsString());
  }

  private JsonNode passwordGrant(String clientId, String username, String scope)
      throws Exception {
    return json(tokenRequest(clientId).param("grant_type", "password")
      .param("username", username)
      .param("password", "password")
      .param("scope", scope));
  }

  private MockHttpServletRequestBuilder refresh(JsonNode token) {
    return tokenRequest("password-grant").param("grant_type", "refresh_token")
      .param("refresh_token", token.path("refresh_token").asText());
  }

  private Set<String> scopes(JsonNode token) {
    String scope = token.path("scope").asText().trim();
    return scope.isEmpty() ? Set.of() : new HashSet<>(Arrays.asList(scope.split("\\s+")));
  }

  private int statusOf(MockHttpServletRequestBuilder request, JsonNode token) throws Exception {
    return mvc
      .perform(request.header(AUTHORIZATION, "Bearer " + token.path("access_token").asText()))
      .andReturn()
      .getResponse()
      .getStatus();
  }

  private int disable(String username, JsonNode token) throws Exception {
    return statusOf(patch("/iam/account/{id}/disable", uuid(username)), token);
  }

  private MockHttpSession login(String username) throws Exception {
    MockHttpSession session =
        (MockHttpSession) mvc.perform(get("/login")).andReturn().getRequest().getSession();

    return (MockHttpSession) mvc
      .perform(post("/login").with(csrf().asHeader())
        .param("username", username)
        .param("password", "password")
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andReturn()
      .getRequest()
      .getSession();
  }

  @Test
  void scopesGrantedDependOnTheRoleOfTheUser() throws Exception {

    JsonNode manager = passwordGrant("password-grant", MANAGER, EVERY_SCOPE);
    JsonNode user = passwordGrant("password-grant", REGULAR_USER, EVERY_SCOPE);
    JsonNode admin = passwordGrant("password-grant", ADMIN, EVERY_SCOPE);

    assertThat(scopes(manager),
        containsInAnyOrder("openid", "offline_access", "iam:user.read", "iam:user.write"));
    assertThat(scopes(user), containsInAnyOrder("openid", "offline_access"));
    assertThat(scopes(admin), containsInAnyOrder(EVERY_SCOPE.split(" ")));

    assertThat(statusOf(get("/scim/Users").param("count", "1"), manager), is(200));
    assertThat(statusOf(get("/scim/Groups"), manager), is(403));
    assertThat(disable(ADMIN, manager), is(403));
    assertThat(disable(USER, manager), is(200));
    assertThat(isActive(USER), is(false));

    assertThat(statusOf(get("/scim/Users"), user), is(403));
    assertThat(disable(MANAGER, user), is(403));
    assertThat(disable(MANAGER, admin), is(200));
  }

  @Test
  void refreshedTokensCanBeDownScopedAndFollowTheRole() throws Exception {

    JsonNode token = passwordGrant("password-grant", MANAGER,
        "openid offline_access iam:user.read iam:user.write");

    JsonNode readOnly = json(refresh(token).param("scope", "openid iam:user.read"));
    assertThat(scopes(readOnly), containsInAnyOrder("openid", "iam:user.read"));
    assertThat(statusOf(get("/scim/Users").param("count", "1"), readOnly), is(200));
    assertThat(disable(USER, readOnly), is(403));

    mvc.perform(refresh(token).param("scope", "openid iam:admin.write"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("invalid_scope")));

    setUserManager(MANAGER, false);

    assertThat(disable(USER, token), is(403));
    assertThat(scopes(json(refresh(token))), containsInAnyOrder("openid", "offline_access"));
    assertThat(isActive(USER), is(true));
  }

  @Test
  void deviceCodeFlowGrantsTheScopesToUserManagersOnly() throws Exception {

    for (String username : new String[] {MANAGER, REGULAR_USER}) {
      JsonNode device = json(post("/devicecode").with(httpBasic("device-code-client", "secret"))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("client_id", "device-code-client")
        .param("scope", EVERY_SCOPE));
      String userCode = device.get("user_code").asText();
      MockHttpSession session = login(username);

      mvc.perform(post("/device/verify").with(csrf().asHeader())
        .param("user_code", userCode)
        .session(session)).andExpect(status().isOk());
      mvc.perform(post("/device/approve").with(csrf().asHeader())
        .param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .session(session)).andExpect(status().isOk());

      JsonNode token = json(tokenRequest("device-code-client")
        .param("grant_type", DEVICE_CODE_GRANT)
        .param("device_code", device.get("device_code").asText()));

      assertThat(scopes(token).contains("iam:user.write"), is(MANAGER.equals(username)));
      assertThat(scopes(token).contains("iam:admin.write"), is(false));
    }
  }

  @Test
  void clientsActingOnTheirOwnAreRestrictedLikeUserManagers() throws Exception {

    JsonNode token = json(tokenRequest("client-cred").param("grant_type", "client_credentials")
      .param("scope", "iam:user.read iam:user.write"));

    assertThat(statusOf(get("/scim/Users").param("count", "1"), token), is(200));
    assertThat(statusOf(get("/scim/Groups"), token), is(403));
    assertThat(disable(ADMIN, token), is(403));
    assertThat(disable(MANAGER, token), is(403));
    assertThat(disable(USER, token), is(200));

    mvc
      .perform(tokenRequest("scim-client-rw").param("grant_type", "client_credentials")
        .param("scope", "iam:user.write"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("invalid_scope")));
  }

  @Test
  void publicAndDynamicallyRegisteredClientsDoNotGetTheScopes() throws Exception {

    JsonNode device = json(post("/devicecode").contentType(APPLICATION_FORM_URLENCODED)
      .param("client_id", "public-dc-client")
      .param("scope", "openid iam:user.write"));

    mvc
      .perform(post("/device/verify").with(csrf().asHeader())
        .param("user_code", device.get("user_code").asText())
        .session(login(MANAGER)))
      .andExpect(status().isBadRequest());

    JsonNode registered = json(post("/iam/api/client-registration")
      .header(AUTHORIZATION,
          "Bearer " + passwordGrant("password-grant", MANAGER, EVERY_SCOPE).path("access_token")
            .asText())
      .contentType(APPLICATION_JSON)
      .content("{\"client_name\":\"oidc-agent:test\","
          + "\"redirect_uris\":[\"http://localhost:4242\"],"
          + "\"grant_types\":[\"" + DEVICE_CODE_GRANT + "\",\"refresh_token\"],"
          + "\"scope\":\"openid offline_access iam:user.read iam:user.write\"}"));

    assertThat(scopes(registered), containsInAnyOrder("openid", "offline_access"));
  }

  @Test
  void exchangedTokensGetTheScopesOnlyForUserManagers() throws Exception {

    for (String username : new String[] {MANAGER, REGULAR_USER}) {
      JsonNode subject =
          passwordGrant("token-exchange-subject", username, "openid iam:user.read");

      JsonNode exchanged = json(tokenRequest("token-exchange-actor")
        .param("grant_type", TOKEN_EXCHANGE_GRANT)
        .param("subject_token", subject.path("access_token").asText())
        .param("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
        .param("scope", "openid iam:user.read"));

      assertThat(scopes(exchanged).contains("iam:user.read"), is(MANAGER.equals(username)));
      assertThat(statusOf(get("/scim/Users").param("count", "1"), exchanged),
          is(MANAGER.equals(username) ? 200 : 403));
      assertThat(disable(USER, exchanged), is(403));
    }
  }
}
