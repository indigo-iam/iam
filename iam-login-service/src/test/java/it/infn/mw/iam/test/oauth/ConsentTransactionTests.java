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

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import javax.servlet.DispatcherType;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import it.infn.mw.iam.persistence.repository.IamConsentGrantRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@IamMockMvcIntegrationTest
@WithMockUser(username = "test", roles = "USER")
class ConsentTransactionTests {

  private static final String CLIENT_A = "client";
  private static final String REDIRECT_A =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  private static final String CLIENT_B = "post-client";
  private static final String REDIRECT_B = "http://localhost:4000/callback";

  // Keep this literal so the test also compiles before the fix.
  private static final String TRANSACTION_PARAMETER = "consent_transaction_id";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamConsentGrantRepository consentGrantRepository;

  @Test
  void rejectsConsentForRequestAAfterRequestBReplacesIt() throws Exception {
    MockHttpSession session = new MockHttpSession();

    // Tab A: display client A's consent page and retain its transaction ID.
    String transactionA = openConsentPage(session, CLIENT_A, REDIRECT_A, "state-a");

    // Tab B: replace the pending request in the same browser session.
    openConsentPage(session, CLIENT_B, REDIRECT_B, "state-b");

    AuthorizationRequest pending =
        (AuthorizationRequest) session.getAttribute("authorizationRequest");

    assertNotNull(pending);
    assertEquals(CLIENT_B, pending.getClientId(),
        "The second request must replace the pending request");
    assertEquals("state-b", pending.getState());

    long consentsBefore = consentGrantRepository.count();

    // Submit the form retained in tab A, with a valid CSRF token.
    MvcResult result = submitConsent(session, transactionA);

    int responseStatus = result.getResponse().getStatus();
    String location = result.getResponse().getHeader("Location");

    assertAll(
        () -> assertEquals(400, responseStatus,
            "A superseded consent form must be rejected locally. " + "Actual status: "
                + responseStatus + ", Location: " + location),
        () -> assertNull(location, "Submitting client A's form must not redirect to client B"),
        () -> assertEquals(consentsBefore, consentGrantRepository.count(),
            "A superseded consent form must not persist a consent grant"));
  }

  @Test
  void acceptsConsentForTheRequestActuallyDisplayed() throws Exception {
    MockHttpSession session = new MockHttpSession();

    String transactionA = openConsentPage(session, CLIENT_A, REDIRECT_A, "state-a");

    assertNotNull(transactionA, "The consent controller must expose consentTransactionId");
    assertTrue(!transactionA.isBlank(), "The consent transaction ID must not be blank");
    AuthorizationRequest pending =
        (AuthorizationRequest) session.getAttribute("authorizationRequest");
    assertNotNull(pending, "The pending authorization request must exist");
    assertEquals(pending.getExtensions().get(TRANSACTION_PARAMETER), transactionA,
        "The displayed transaction ID must match the pending request");

    MvcResult result = submitConsent(session, transactionA);

    String body = result.getResponse().getContentAsString();

    assertEquals(303, result.getResponse().getStatus(),
        "Expected successful authorization redirect." + "\nStatus: "
            + result.getResponse().getStatus() + "\nError: "
            + result.getResponse().getErrorMessage() + "\nException: "
            + result.getResolvedException() + "\nLocation: "
            + result.getResponse().getHeader("Location") + "\nBody: " + body);
    assertTrue(result.getResponse().getStatus() >= 300 && result.getResponse().getStatus() < 400,
        "A valid consent submission must complete authorization");

    String location = result.getResponse().getHeader("Location");
    assertNotNull(location);
    assertTrue(location.startsWith(REDIRECT_A + "?"),
        "The authorization response must target client A");

    UriComponents redirect = UriComponentsBuilder.fromUriString(location).build();

    assertEquals("state-a", redirect.getQueryParams().getFirst("state"));
    assertNotNull(redirect.getQueryParams().getFirst("code"),
        "Successful authorization must issue an authorization code");
    assertNull(redirect.getQueryParams().getFirst("error"));
  }

  private MvcResult renderConsentPage(MockHttpSession session) throws Exception {
    Authentication authentication = TestSecurityContextHolder.getContext().getAuthentication();

    assertNotNull(authentication, "@WithMockUser must provide the authenticated test user");

    SecurityContext previousContext = SecurityContextHolder.getContext();
    SecurityContext forwardContext = SecurityContextHolder.createEmptyContext();
    forwardContext.setAuthentication(authentication);

    try {
      // A real internal forward executes within the authenticated request.
      SecurityContextHolder.setContext(forwardContext);

      return mvc.perform(
          get("/oauth/confirm_access").session(session).principal(authentication).with(request -> {
            request.setDispatcherType(DispatcherType.FORWARD);
            return request;
          }))
        .andExpect(status().isOk())
        .andExpect(view().name("iam/approveClient"))
        .andReturn();

    } finally {
      SecurityContextHolder.setContext(previousContext);
    }
  }

  private String openConsentPage(MockHttpSession session, String clientId, String redirectUri,
      String state) throws Exception {

    mvc
      .perform(get("/authorize").session(session)
        .param("client_id", clientId)
        .param("redirect_uri", redirectUri)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("state", state)
        .param("prompt", "consent"))
      .andExpect(status().isOk())
      .andExpect(view().name("forward:/oauth/confirm_access"));

    MvcResult consentPage = renderConsentPage(session);
    assertNotNull(consentPage.getModelAndView());

    AuthorizationRequest displayed =
        (AuthorizationRequest) consentPage.getModelAndView().getModel().get("auth_request");

    assertNotNull(displayed);
    assertEquals(clientId, displayed.getClientId());
    assertEquals(redirectUri, displayed.getRedirectUri());
    assertEquals(state, displayed.getState());

    // Before the fix, this attribute is absent. Do not fail here:
    // the regression test must reach the vulnerable approval endpoint.
    return (String) consentPage.getModelAndView().getModel().get("consent_transaction_id");
  }

  private MvcResult submitConsent(MockHttpSession session, String transactionId) throws Exception {

    MockHttpServletRequestBuilder request = post("/authorize").session(session)
      .with(csrf())
      .param("user_oauth_approval", "true")
      .param("scope.openid", "true")
      .param("authorize", "Authorize")
      .param("remember", "until-revoked");

    if (transactionId != null) {
      request.param(TRANSACTION_PARAMETER, transactionId);
    }

    return mvc.perform(request).andDo(print()).andReturn();
  }
}
