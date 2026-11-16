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

import static it.infn.mw.iam.test.oauth.authzcode.AuthorizationCodeMockMvcHelper.CLIENT_ID;
import static it.infn.mw.iam.test.oauth.authzcode.AuthorizationCodeMockMvcHelper.REDIRECT_URI;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.time.Clock;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.data.domain.Pageable;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.NestedServletException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

// Use the real resource-server filter: bearer-token authorization is under test.
@SpringBootTest(classes = IamLoginService.class, webEnvironment = WebEnvironment.MOCK,
    properties = "iam.access_token.include_scope=true")
@AutoConfigureMockMvc
@ActiveProfiles({"h2-test", "wlcg-scopes"})
@Transactional
class AuthorizationCodeIntegrationTests {

  private static final String RESOURCE_1 = "http://example1.org";
  private static final String RESOURCE_2 = "http://example2.org";
  private static final String FULL_RESOURCE = RESOURCE_1 + " " + RESOURCE_2;

  @Autowired
  private MockMvc mvc;
  @Autowired
  private ObjectMapper mapper;
  @Autowired
  private IamOAuthRefreshTokenRepository refreshTokenRepository;
  @Autowired
  private Clock clock;

  private AuthorizationCodeMockMvcHelper flow;

  @BeforeEach
  void setup() {
    TestSecurityContextHolder.clearContext();
    flow = new AuthorizationCodeMockMvcHelper(mvc, mapper);
  }

  @Test
  void testAuthzCodeMissingClientId() throws Exception {
    flow.authorize(null, null, Map.of("resource", FULL_RESOURCE))
      .andExpect(status().isUnauthorized());
  }

  @Test
  void testAuthzCodeSupportsClaimsRequestParameter() throws Exception {
    // Preserve the original assertion: anonymous requests reach login.
    // This does not establish that the claims value is valid OIDC JSON.
    flow.authorize(null, CLIENT_ID, Map.of("claims", "email", "resource", FULL_RESOURCE))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("http://localhost/login"));
  }

  @Test
  void testAuthzCodeAudienceSupport() throws Exception {
    for (String audienceKey : List.of("aud", "audience")) {
      JsonNode tokens = issueTokens(Map.of(audienceKey, "example-audience"), Map.of());
      assertAudience(tokens, "access_token", "example-audience");
      assertAudience(tokens, "id_token", CLIENT_ID);
    }
  }

  @Test
  void testAuthzCodeResourceIndicatorSupport() throws Exception {
    JsonNode tokens =
        issueTokens(Map.of("resource", FULL_RESOURCE), Map.of("resource", FULL_RESOURCE));
    assertAudience(tokens, "access_token", RESOURCE_1, RESOURCE_2);
  }

  @Test
  void testAuthzCodeResourceIndicatorNotOriginallyGranted() throws Exception {
    String code = flow.authorizationCode(Map.of("resource", FULL_RESOURCE));
    flow.exchange(code, REDIRECT_URI, Map.of("resource", "http://example3.org"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description")
        .value("The requested resource was not originally granted"));
  }

  @Test
  void testAuthzCodeEmptyResourceIndicator() throws Exception {
    JsonNode tokens = issueTokens(Map.of("resource", FULL_RESOURCE), Map.of());
    assertAudience(tokens, "access_token", RESOURCE_1, RESOURCE_2);
  }

  @Test
  void testRefreshTokenAfterAuthzCodeWorks() throws Exception {
    refreshTokenRepository.deleteAll();
    JsonNode tokens = issueTokens(Map.of(), Map.of());
    verifyForbiddenEndpointsForTestUserWithToken(flow.requiredToken(tokens, "access_token"));

    List<OAuth2RefreshTokenEntity> refreshTokens = refreshTokenRepository
      .findValidRefreshTokensForUserAndClient("test", CLIENT_ID, Date.from(clock.instant()),
          Pageable.unpaged())
      .getContent();
    assertThat(refreshTokens, hasSize(1));
    // Each restricted scope must be absent (stronger than not(hasItems(...))).
    for (String forbidden : List.of("iam:admin.read", "iam:admin.write", "scim:read",
        "scim:write")) {
      assertThat(refreshTokens.get(0).getAuthenticationHolder().getScope(),
          not(hasItem(forbidden)));
    }

    String refreshToken = flow.requiredToken(tokens, "refresh_token");
    JsonNode narrowed = flow.successfulJson(flow.refresh(refreshToken, "openid", Map.of()));
    verifyForbiddenEndpointsForTestUserWithToken(flow.requiredToken(narrowed, "access_token"));

    for (String requested : List.of("openid iam:admin.read iam:admin.write",
        "openid scim:read scim:write")) {
      flow.refresh(refreshToken, requested, Map.of())
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value("invalid_scope"))
        .andExpect(jsonPath("$.error_description").value("Up-scoping is not allowed."));
    }

    JsonNode full = flow.successfulJson(flow.refresh(refreshToken, null, Map.of()));
    verifyForbiddenEndpointsForTestUserWithToken(flow.requiredToken(full, "access_token"));
  }

  @Test
  void testNarrowerResourceIndicatorRTFlowAfterAuthzCode() throws Exception {
    assertRefreshAudience(true, "resource", RESOURCE_1, RESOURCE_1);
  }

  @Test
  void testFilteredResourceIndicatorRTFlowAfterAuthzCode() throws Exception {
    assertRefreshAudience(true, "resource", RESOURCE_1 + " http://example3.org", RESOURCE_1);
  }

  @Test
  void testFilteredResourceIndicatorWithAudRequestRTFlowAfterAuthzCode() throws Exception {
    assertRefreshAudience(false, "audience", RESOURCE_1 + " http://example3.org", RESOURCE_1);
  }

  @Test
  void testResourceIndicatorRTFlowBoundToAuthzCode() throws Exception {
    assertRefreshAudience(false, "resource", FULL_RESOURCE, RESOURCE_1, RESOURCE_2);
  }

  @Test
  void testNullAuthorizationCode() throws Exception {
    flow.authorizationCode(Map.of());
    flow.exchange(null, REDIRECT_URI, Map.of())
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_request"))
      .andExpect(jsonPath("$.error_description").value("An authorization code must be supplied."));
  }

  @Test
  void testFakeAuthorizationCode() throws Exception {
    flow.authorizationCode(Map.of());
    flow.exchange("1234", REDIRECT_URI, Map.of())
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_grant"))
      .andExpect(jsonPath("$.error_description")
        .value("JpaAuthorizationCodeRepository: no authorization code found for value 1234"));
  }

  @Test
  void testRedirectURIMismatch() throws Exception {
    String code = flow.authorizationCode(Map.of());
    flow.exchange(code, "http://fake.redirect.uri.org", Map.of())
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_grant"))
      .andExpect(jsonPath("$.error_description").value("Redirect URI mismatch."));
  }

  @Test
  void testClientIDMismatch() throws Exception {
    String code = flow.authorizationCode(Map.of());
    flow.exchange(code, REDIRECT_URI, Map.of("client_id", "fake-client-id"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error").value("invalid_client"))
      .andExpect(jsonPath("$.error_description")
        .value("Given client ID does not match authenticated client"));
  }

  @Test
  void testUnverifiedUserCannotGetAToken() throws Exception {
    MockHttpSession session = flow.startBrowserSession("unverified-user", Map.of());

    flow.authorize(session, CLIENT_ID, Map.of())
      .andExpect(status().isOk())
      .andExpect(view().name("forward:/oauth/confirm_access"));

    NestedServletException exception =
        assertThrows(NestedServletException.class, () -> flow.renderConsent(session));

    assertTrue(exception.getRootCause() instanceof AccessDeniedException,
        () -> "Expected consent access to be denied, but got: " + exception.getRootCause());
  }

  @Test
  void testUsingCodeTwiceIsBadRequest() throws Exception {
    String code = flow.authorizationCode(Map.of());
    flow.exchange(code, REDIRECT_URI, Map.of()).andExpect(status().isOk());
    flow.exchange(code, REDIRECT_URI, Map.of()).andExpect(status().isBadRequest());
  }

  private JsonNode issueTokens(Map<String, String> authorizationParameters,
      Map<String, String> tokenParameters) throws Exception {
    String code = flow.authorizationCode(authorizationParameters);
    return flow.successfulJson(flow.exchange(code, REDIRECT_URI, tokenParameters));
  }

  private void assertRefreshAudience(boolean includeResourceAtTokenEndpoint, String parameter,
      String value, String... expectedAudience) throws Exception {
    refreshTokenRepository.deleteAll();
    JsonNode tokens = issueTokens(Map.of("resource", FULL_RESOURCE),
        includeResourceAtTokenEndpoint ? Map.of("resource", FULL_RESOURCE) : Map.of());
    JsonNode refreshed = flow.successfulJson(flow
      .refresh(flow.requiredToken(tokens, "refresh_token"), "openid", Map.of(parameter, value)));
    assertAudience(refreshed, "access_token", expectedAudience);
  }

  private void assertAudience(JsonNode tokens, String tokenName, String... expected)
      throws Exception {
    List<String> actual =
        JWTParser.parse(flow.requiredToken(tokens, tokenName)).getJWTClaimsSet().getAudience();
    assertThat(actual, hasSize(expected.length));
    assertThat(actual, hasItems(expected));
  }

  private void verifyForbiddenEndpointsForTestUserWithToken(String token) throws Exception {
    TestSecurityContextHolder.clearContext();
    for (String endpoint : List.of("/scim/Users", "/scim/Groups",
        "/scim/Users/f2ce8cb2-a1db-4884-9ef0-d8842cc02b4a",
        "/scim/Groups/c617d586-54e6-411d-8e38-649677980001",
        "/iam/group/c617d586-54e6-411d-8e38-649677980001/attributes",
        "/iam/account/80e5fb8d-b7c8-451a-89ba-346ae278a66f/authorities", "/iam/api/clients",
        "/iam/scope_policies")) {
      mvc.perform(get(endpoint).header("Authorization", "Bearer " + token))
        .andExpect(status().isForbidden());
    }
    for (String endpoint : List.of("/scim/Users/80e5fb8d-b7c8-451a-89ba-346ae278a66f",
        "/scim/Groups/c617d586-54e6-411d-8e38-649677980001")) {
      mvc.perform(delete(endpoint).header("Authorization", "Bearer " + token))
        .andExpect(status().isForbidden());
    }
  }
}
