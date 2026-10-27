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

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.persistence.EntityManager;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.ModelAndView;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;

@SpringBootTest(classes = IamLoginService.class, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("h2-test")
@Transactional
public class ScopesFilterTests extends ScopePolicyTestUtils {

  public static final String TEST_CLIENT_ID = "client";
  public static final String RESPONSE_TYPE_CODE = "code";
  public static final String EMAIL = "email";
  public static final String SCOPE = "openid email";
  public static final String SCOPE_ADMIN = "iam:admin.write";

  public static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamScopePolicyRepository policyScopeRepo;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private EntityManager em;

  private IamAccount findTestAccount() {
    return accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found!"));
  }

  private MockHttpServletRequestBuilder authorizationRequest(String clientId, String scope) {

    return get("/authorize").param("response_type", RESPONSE_TYPE_CODE)
      .param("client_id", clientId)
      .param("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .param("scope", scope)
      .param("nonce", "1")
      .param("state", "1");
  }

  private MvcResult getConsentPage(String username, String clientId, String scope)
      throws Exception {

    MvcResult authorizationResult = mvc.perform(authorizationRequest(clientId, scope))
      .andExpect(status().isFound())
      .andReturn();

    MockHttpSession session = (MockHttpSession) authorizationResult.getRequest().getSession(false);

    assertNotNull(session, "Authorization request must create a login session");

    MvcResult loginResult = mvc
      .perform(post("/login").session(session)
        .with(csrf().asHeader())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("username", username)
        .param("password", "password")
        .param("submit", "Login"))
      .andExpect(status().isFound())
      .andExpect(authenticated().withUsername(username))
      .andReturn();

    // Use the session returned after authentication, including any
    // session fixation protection applied during login.
    MockHttpSession authenticatedSession =
        (MockHttpSession) loginResult.getRequest().getSession(false);

    assertNotNull(authenticatedSession, "Login must retain an authenticated session");

    return mvc.perform(authorizationRequest(clientId, scope).session(authenticatedSession))
      .andExpect(status().isOk())
      .andDo(print())
      .andReturn();
  }

  private Set<String> consentScopes(MvcResult result) {

    assertEquals("/oauth/confirm_access", result.getResponse().getForwardedUrl(),
        "Expected a forward to the consent controller");

    ModelAndView modelAndView = result.getModelAndView();

    assertNotNull(modelAndView, "Expected the authorization endpoint model");

    Object attribute = modelAndView.getModel().get("scope");

    assertTrue(attribute instanceof String,
        "Expected a 'scope' string in the model; available attributes: "
            + modelAndView.getModel().keySet());

    String scope = ((String) attribute).trim();

    if (scope.isEmpty()) {
      return Set.of();
    }

    return Arrays.stream(scope.split("\\s+")).collect(Collectors.toSet());
  }

  @Test
  void testConsentPageReturnsFilteredScopes() throws Exception {

    IamAccount testAccount = findTestAccount();

    IamScopePolicy policy = initDenyScopePolicy();
    policy.linkAccount(testAccount);
    policy.setScopes(Set.of(EMAIL));

    policy = policyScopeRepo.save(policy);
    em.flush();
    accountRepo.save(testAccount);
    em.flush();

    List<IamScopePolicy> accountPolicies = policyScopeRepo.findByAccount(testAccount);

    assertThat(accountPolicies, not(empty()));
    assertThat(findTestAccount().getScopePolicies(), hasItem(policy));

    Set<String> scopes = consentScopes(getConsentPage("test", TEST_CLIENT_ID, SCOPE));

    assertFalse(scopes.contains(EMAIL));
    assertEquals(Set.of(OPENID), scopes);
  }

  @Test
  void testConsentPageDoesNotReturnAdminScopeToRegularUser() throws Exception {

    Set<String> scopes = consentScopes(getConsentPage("test", "admin-client-rw", SCOPE_ADMIN));

    assertFalse(scopes.contains(SCOPE_ADMIN));
    assertTrue(scopes.isEmpty());
  }

  @Test
  void testConsentPageReturnsAdminScopeToAdmins() throws Exception {

    Set<String> scopes = consentScopes(getConsentPage("admin", TEST_CLIENT_ID, SCOPE_ADMIN));

    assertTrue(scopes.contains(SCOPE_ADMIN));
  }
}
