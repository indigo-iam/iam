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

    for (String clientId : new String[] {"password-grant", "client-cred"}) {
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
}
