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
package it.infn.mw.iam.test.oauth.authzcode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.Map;
import javax.servlet.DispatcherType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Browser-session operations and independent client/token requests. */
final class AuthorizationCodeMockMvcHelper {

  static final String CLIENT_ID = "client";
  static final String CLIENT_SECRET = "secret";
  static final String REDIRECT_URI = "https://iam.local.io/iam-test-client/openid_connect_login";
  static final String SCOPE =
      "openid profile scim:read scim:write offline_access " + "iam:admin.read iam:admin.write";
  private static final String TRANSACTION_ID = "consent_transaction_id";

  private final MockMvc mvc;
  private final ObjectMapper mapper;

  AuthorizationCodeMockMvcHelper(MockMvc mvc, ObjectMapper mapper) {
    this.mvc = mvc;
    this.mapper = mapper;
  }

  ResultActions authorize(MockHttpSession session, String clientId, Map<String, String> extra)
      throws Exception {
    TestSecurityContextHolder.clearContext();
    MockHttpServletRequestBuilder request = get("/authorize").param("response_type", "code")
      .param("redirect_uri", REDIRECT_URI)
      .param("scope", SCOPE)
      .param("nonce", "1")
      .param("state", "1");
    if (session != null) {
      request.session(session);
    }
    if (clientId != null) {
      request.param("client_id", clientId);
    }
    extra.forEach((key, value) -> request.param(key, value));
    return mvc.perform(request);
  }

  MockHttpSession login(MockHttpSession session, String username) throws Exception {
    TestSecurityContextHolder.clearContext();
    MvcResult result = mvc
      .perform(post("/login").session(session)
        .with(csrf())
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("username", username)
        .param("password", "password")
        .param("submit", "Login"))
      .andExpect(status().isFound())
      .andReturn();
    MockHttpSession authenticated = (MockHttpSession) result.getRequest().getSession(false);
    assertNotNull(authenticated);
    SecurityContext context = (SecurityContext) authenticated
      .getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
    assertNotNull(context, "Login must establish an authenticated session");
    assertNotNull(context.getAuthentication());
    assertEquals(username, context.getAuthentication().getName());
    return authenticated;
  }

  MockHttpSession startBrowserSession(String username, Map<String, String> extra) throws Exception {
    MvcResult initial = authorize(null, CLIENT_ID, extra).andExpect(status().isFound())
      .andExpect(redirectedUrl("http://localhost/login"))
      .andReturn();
    MockHttpSession session = (MockHttpSession) initial.getRequest().getSession(false);
    assertNotNull(session);
    return login(session, username);
  }

  String authorizationCode(Map<String, String> extra) throws Exception {
    MockHttpSession session = startBrowserSession("test", extra);
    authorize(session, CLIENT_ID, extra).andExpect(status().isOk())
      .andExpect(view().name("forward:/oauth/confirm_access"));

    MvcResult page = renderConsent(session);
    assertNotNull(page.getModelAndView());
    String transactionId = (String) page.getModelAndView().getModel().get(TRANSACTION_ID);
    assertNotNull(transactionId, "Consent page must expose " + TRANSACTION_ID);
    assertFalse(transactionId.isBlank());

    TestSecurityContextHolder.clearContext();
    MvcResult approval = mvc
      .perform(post("/authorize").session(session)
        .with(csrf())
        .contentType(APPLICATION_FORM_URLENCODED)
        .param(TRANSACTION_ID, transactionId)
        .param("user_oauth_approval", "true")
        .param("authorize", "Authorize")
        .param("remember", "none"))
      .andExpect(status().isSeeOther())
      .andReturn();
    String location = approval.getResponse().getHeader("Location");
    assertNotNull(location);
    var redirect = UriComponentsBuilder.fromUriString(location).build();
    assertEquals(REDIRECT_URI,
        UriComponentsBuilder.fromUriString(location)
          .replaceQuery(null)
          .fragment(null)
          .build()
          .toUriString());
    assertEquals("1", redirect.getQueryParams().getFirst("state"));
    assertNull(redirect.getQueryParams().getFirst("error"));
    String code = redirect.getQueryParams().getFirst("code");
    assertNotNull(code, "Missing authorization code in " + location);
    return code;
  }

  MvcResult renderConsent(MockHttpSession session) throws Exception {
    SecurityContext sessionContext = (SecurityContext) session
      .getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
    assertNotNull(sessionContext);
    Authentication authentication = sessionContext.getAuthentication();
    assertNotNull(authentication);
    SecurityContext previous = SecurityContextHolder.getContext();
    SecurityContext forwardContext = SecurityContextHolder.createEmptyContext();
    forwardContext.setAuthentication(authentication);
    try {
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
      SecurityContextHolder.setContext(previous);
    }
  }

  ResultActions exchange(String code, String redirectUri, Map<String, String> extra)
      throws Exception {
    MockHttpServletRequestBuilder request = post("/token").contentType(APPLICATION_FORM_URLENCODED)
      .param("grant_type", "authorization_code")
      .param("state", "1");
    if (code != null) {
      request.param("code", code);
    }
    if (redirectUri != null) {
      request.param("redirect_uri", redirectUri);
    }
    extra.forEach((key, value) -> request.param(key, value));
    return clientRequest(request);
  }

  ResultActions refresh(String refreshToken, String scope, Map<String, String> extra)
      throws Exception {
    MockHttpServletRequestBuilder request = post("/token").contentType(APPLICATION_FORM_URLENCODED)
      .param("grant_type", "refresh_token")
      .param("refresh_token", refreshToken);
    if (scope != null) {
      request.param("scope", scope);
    }
    extra.forEach((key, value) -> request.param(key, value));
    return clientRequest(request);
  }

  private ResultActions clientRequest(MockHttpServletRequestBuilder request) throws Exception {
    TestSecurityContextHolder.clearContext();
    // Deliberately no browser session, user principal, or CSRF helper here.
    return mvc.perform(request.with(httpBasic(CLIENT_ID, CLIENT_SECRET)));
  }

  JsonNode successfulJson(ResultActions response) throws Exception {
    return mapper
      .readTree(response.andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
  }

  String requiredToken(JsonNode response, String field) {
    JsonNode value = response.get(field);
    assertNotNull(value, "Missing " + field + " in token response");
    assertTrue(value.isTextual());
    assertFalse(value.asText().isBlank());
    return value.asText();
  }
}
