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
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.List;

import javax.servlet.DispatcherType;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@ActiveProfiles({"h2-test", "wlcg-scopes"})
@TestPropertySource(properties = "iam.access_token.include_scope=true")
@WithMockUser(username = "test", roles = "USER")
class AuthorizationCodeResourceIndicatorTests {

  private static final String CLIENT_ID = "client";
  private static final String CLIENT_SECRET = "secret";

  private static final String REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  private static final String SCOPE =
      "openid profile scim:read scim:write offline_access " + "iam:admin.read iam:admin.write";

  private static final String CONSENT_TRANSACTION_ID = "consent_transaction_id";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Test
  void testNarrowerResourceIndicator() throws Exception {
    JsonNode tokens = getTokenResponseWithAudience("resource", "resource",
        "http://example1.org http://example2.org", "http://example1.org");

    assertAudience(tokens, "http://example1.org");
  }

  @Test
  void testFilteredResourceIndicator() throws Exception {
    JsonNode tokens = getTokenResponseWithAudience("resource", "resource",
        "http://storm.org http://dcache.org", "http://storm.org http://rucio.org");

    assertAudience(tokens, "http://storm.org");
  }

  @Test
  void testFilteredResourceIndicatorWithAudRequest() throws Exception {
    JsonNode tokens = getTokenResponseWithAudience("resource", "audience",
        "http://1.org http://2.org", "http://1.org http://3.org");

    assertAudience(tokens, "http://1.org");
  }

  private JsonNode getTokenResponseWithAudience(String resourceParamAuthz,
      String resourceParamToken, String resourceValueAuthz, String resourceValueToken)
      throws Exception {

    MockHttpSession session = new MockHttpSession();

    mvc
      .perform(get("/authorize").session(session)
        .param("response_type", "code")
        .param("client_id", CLIENT_ID)
        .param("redirect_uri", REDIRECT_URI)
        .param("scope", SCOPE)
        .param(resourceParamAuthz, resourceValueAuthz)
        .param("nonce", "1")
        .param("state", "resource-test")
        .param("prompt", "consent"))
      .andExpect(status().isOk())
      .andExpect(view().name("forward:/oauth/confirm_access"));

    MvcResult consentPage = renderConsentPage(session);

    assertNotNull(consentPage.getModelAndView());

    String transactionId =
        (String) consentPage.getModelAndView().getModel().get(CONSENT_TRANSACTION_ID);

    assertNotNull(transactionId, "The consent controller must expose consent_transaction_id");
    assertFalse(transactionId.isBlank(), "The consent transaction ID must not be blank");

    MvcResult approval = mvc
      .perform(post("/authorize").session(session)
        .with(csrf())
        .contentType(APPLICATION_FORM_URLENCODED)
        .param(CONSENT_TRANSACTION_ID, transactionId)
        .param("user_oauth_approval", "true")
        .param("authorize", "Authorize")
        .param("remember", "none"))
      .andExpect(status().isSeeOther())
      .andReturn();

    String location = approval.getResponse().getHeader("Location");
    assertNotNull(location, "Authorization must return a redirect");

    var redirect = UriComponentsBuilder.fromUriString(location).build();

    assertEquals(REDIRECT_URI,
        UriComponentsBuilder.fromUriString(location)
          .replaceQuery(null)
          .fragment(null)
          .build()
          .toUriString());

    assertEquals("resource-test", redirect.getQueryParams().getFirst("state"));

    String code = redirect.getQueryParams().getFirst("code");
    assertNotNull(code, "Expected an authorization code in redirect: " + location);

    // The token request is authenticated as the client, not the browser user.
    TestSecurityContextHolder.clearContext();

    MvcResult tokenResponse = mvc
      .perform(post("/token").with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("grant_type", "authorization_code")
        .param("redirect_uri", REDIRECT_URI)
        .param("code", code)
        .param(resourceParamToken, resourceValueToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").isNotEmpty())
      .andReturn();

    return mapper.readTree(tokenResponse.getResponse().getContentAsString());
  }

  private MvcResult renderConsentPage(MockHttpSession session) throws Exception {

    Authentication authentication = TestSecurityContextHolder.getContext().getAuthentication();

    assertNotNull(authentication, "@WithMockUser must provide the authenticated test user");

    SecurityContext previousContext = SecurityContextHolder.getContext();
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
      SecurityContextHolder.setContext(previousContext);
    }
  }

  private void assertAudience(JsonNode tokens, String expectedAudience) throws Exception {

    List<String> audience =
        JWTParser.parse(tokens.get("access_token").asText()).getJWTClaimsSet().getAudience();

    assertEquals(List.of(expectedAudience), audience);
  }
}
