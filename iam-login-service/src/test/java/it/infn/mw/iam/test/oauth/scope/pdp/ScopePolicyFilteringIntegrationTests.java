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
package it.infn.mw.iam.test.oauth.scope.pdp;

import static com.google.common.collect.Sets.newHashSet;
import static it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy.PATH;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@TestPropertySource(properties = {"iam.access_token.include_scope=true"})
@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(
// @formatter:off
    properties = {
        "scope.matchers[0].name=read", 
        "scope.matchers[0].type=path",
        "scope.matchers[0].prefix=read", 
        "scope.matchers[0].path=/",
        "scope.matchers[1].name=write", 
        "scope.matchers[1].type=path",
        "scope.matchers[1].prefix=write", 
        "scope.matchers[1].path=/",
   // @formatter:on
    })
public class ScopePolicyFilteringIntegrationTests extends ScopePolicyTestUtils {

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

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();

  }

  @Test
  public void testPasswordFlowScopeFilteringByAccountWorks() throws Exception {

    IamAccount testAccount = findTestAccount();

    IamScopePolicy up = initDenyScopePolicy();
    up.setAccount(testAccount);
    up.setRule(PolicyRule.DENY);
    up.setScopes(Sets.newHashSet(SCIM_READ));

    scopePolicyRepo.save(up);

    String clientId = "password-grant";
    String clientSecret = "secret";

    mvc
      .perform(post("/token").with(httpBasic(clientId, clientSecret))
        .param("grant_type", "password")
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid profile scim:read"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", equalTo("openid profile")));

    scopePolicyRepo.delete(up);
  }

  @Test
  public void testPasswordFlowDenyAllScopesWorksExceptForOpenidScope() throws Exception {

    IamAccount testAccount = findTestAccount();

    IamScopePolicy up = initDenyScopePolicy();
    up.setAccount(testAccount);
    scopePolicyRepo.save(up);

    String clientId = "password-grant";
    String clientSecret = "secret";

    mvc
      .perform(post("/token").with(httpBasic(clientId, clientSecret))
        .param("grant_type", "password")
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid scim:read"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", equalTo("openid")))
      .andExpect(jsonPath("$.id_token").exists());

    mvc
      .perform(post("/token").with(httpBasic(clientId, clientSecret))
        .param("grant_type", "password")
        .param("username", "test")
        .param("password", "password")
        .param("scope", "profile scim:read"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope").doesNotExist())
      .andExpect(jsonPath("$.id_token").doesNotExist());

    scopePolicyRepo.delete(up);

  }

  @Test
  public void testAuthzCodeFlowScopeFilteringByAccountWorks() throws Exception {

    IamAccount testAccount = findTestAccount();

    IamScopePolicy up = initDenyScopePolicy();
    up.setAccount(testAccount);
    up.setScopes(Sets.newHashSet("read-tasks"));

    scopePolicyRepo.save(up);

    String clientId = "client";

    MockHttpSession session = (MockHttpSession) mvc
      .perform(get("/authorize").param("scope", "openid profile read-tasks")
        .param("response_type", "code")
        .param("client_id", clientId)
        .param("redirect_uri", "https://iam.local.io/iam-test-client/openid_connect_login")
        .param("state", "1234567"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/login").param("username", "test")
        .param("password", "password")
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/authorize"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc
      .perform(get("/authorize").session(session)
        .param("scope", "openid profile read-tasks")
        .param("response_type", "code")
        .param("client_id", clientId)
        .param("redirect_uri", "https://iam.local.io/iam-test-client/openid_connect_login")
        .param("state", "1234567"))
      .andExpect(status().isOk())
      .andExpect(forwardedUrl("/oauth/confirm_access"))
      .andExpect(model().attribute("scope", equalTo("openid profile")))
      .andReturn()
      .getRequest()
      .getSession();

    scopePolicyRepo.delete(up);

  }

  @Test
  public void testMatchingPolicyFilteringWorks() throws Exception {

    IamScopePolicy up = initDenyScopePolicy();
    up.setRule(PolicyRule.DENY);
    up.setScopes(newHashSet("read:/", "write:/"));
    up.setMatchingPolicy(PATH);

    scopePolicyRepo.save(up);

    String clientId = "client";

    MockHttpSession session = (MockHttpSession) mvc
      .perform(get("/authorize").param("scope", "openid profile read:/ read:/that/thing write:/")
        .param("response_type", "code")
        .param("client_id", clientId)
        .param("redirect_uri", "https://iam.local.io/iam-test-client/openid_connect_login")
        .param("state", "1234567"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/login").param("username", "test")
        .param("password", "password")
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/authorize"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc
      .perform(get("/authorize").session(session)
        .param("scope", "openid profile read:/ read:/that/thing write:/")
        .param("response_type", "code")
        .param("client_id", clientId)
        .param("redirect_uri", "https://iam.local.io/iam-test-client/openid_connect_login")
        .param("state", "1234567"))
      .andExpect(status().isOk())
      .andExpect(forwardedUrl("/oauth/confirm_access"))
      .andExpect(model().attribute("scope", equalTo("openid profile")))
      .andReturn()
      .getRequest()
      .getSession();

    scopePolicyRepo.delete(up);

  }

  @Test
  public void testRefreshTokenAfterPasswordFlowSystemScopeFilteringWorks() throws Exception {

    IamAccount testAccount = findTestAccount();

    IamScopePolicy up = initDenyScopePolicy();
    up.setAccount(testAccount);
    up.setScopes(Sets.newHashSet("profile"));

    scopePolicyRepo.save(up);

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", "password-grant")
        .param("client_secret", "secret")
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid profile offline_access"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponseJson).get("refresh_token").asText();

    tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", "password-grant")
        .param("client_secret", "secret")
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertTrue(claims.getStringClaim("scope").contains("openid"));
    assertTrue(claims.getStringClaim("scope").contains("offline_access"));
    assertFalse(claims.getStringClaim("scope").contains("profile"));

    scopePolicyRepo.delete(up);

  }

}
