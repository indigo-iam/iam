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
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Joiner;
import com.google.common.collect.Sets;
import com.nimbusds.jwt.SignedJWT;

import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;


@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
@TestPropertySource(
// @formatter:off
  properties = {
    "iam.access_token.include_scope=true"
  }
  // @formatter:on
)
@ActiveProfiles({"h2", "wlcg-scopes"})
public class AuthZCodeIntegrationTests extends ScopePolicyTestUtils {

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamScopePolicyRepository scopePolicyRepo;

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  protected ObjectMapper mapper;

  @Value("${local.server.port}")
  private Integer iamPort;

  private String loginUrl;
  private String authorizeUrl;
  private String tokenUrl;

  public static final String LOCALHOST_URL_TEMPLATE = "http://localhost:%d";

  IamAccount findTestAccount() {
    return accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found!"));
  }

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();

  }

  @Before
  public void setup() {
    RestAssured.port = iamPort;
    loginUrl = String.format(LOCALHOST_URL_TEMPLATE + "/login", iamPort);
    authorizeUrl = String.format(LOCALHOST_URL_TEMPLATE + "/authorize", iamPort);
    tokenUrl = String.format(LOCALHOST_URL_TEMPLATE + "/token", iamPort);
  }

  @Test
  public void testRefreshTokenAfterAuthzCodeFiltersWLCGScopes() throws IOException, ParseException {

    final String TEST_USER_NAME = "test";
    final String TEST_USER_PASSWORD = "password";
    final String TEST_CLIENT_ID = "refresh-client";
    final String TEST_CLIENT_SECRET = "secret";
    final String TEST_CLIENT_REDIRECT_URI = "http://localhost:4000/callback";

    final Set<String> ALL_SCOPES =
        Set.of("openid", "profile", "offline_access", "storage.read:/path", "storage.write:/path",
            "storage.read:/", "storage.write:/", "storage.read:/another/path");
    final Set<String> ALLOWED_SCOPES =
        Set.of("openid", "profile", "offline_access", "storage.read:/path", "storage.write:/path");
    final Set<String> NO_SCOPES = Set.of();

    ClientDetailsEntity client = clientRepo.findByClientId(TEST_CLIENT_ID).orElseThrow();
    assertThat(client.getScope(), hasItems("storage.read:/", "storage.write:/"));

    ValidatableResponse authzCodeResponse =
        authorizationCodeFlow(TEST_CLIENT_ID, TEST_CLIENT_SECRET, TEST_CLIENT_REDIRECT_URI,
            TEST_USER_NAME, TEST_USER_PASSWORD, Joiner.on(" ").join(ALL_SCOPES));

    String responseAsString = authzCodeResponse.extract().body().asString();
    String accessToken = mapper.readTree(responseAsString).get("access_token").asText();
    String refreshToken = mapper.readTree(responseAsString).get("refresh_token").asText();

    checkAccessTokenScopes(accessToken, ALL_SCOPES);

    accessToken = refreshTokenWithScopes(refreshToken, ALL_SCOPES);
    checkAccessTokenScopes(accessToken, ALL_SCOPES);

    // add deny policies
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

    // refresh again and check policies are applied

    accessToken = refreshTokenWithScopes(refreshToken, ALL_SCOPES);
    checkAccessTokenScopes(accessToken, ALLOWED_SCOPES);

    accessToken = refreshTokenWithScopes(refreshToken, NO_SCOPES);
    checkAccessTokenScopes(accessToken, ALLOWED_SCOPES);

    accessToken = refreshTokenWithScopes(refreshToken, Set.of("storage.read:/"));
    checkAccessTokenScopes(accessToken, NO_SCOPES);

    accessToken = refreshTokenWithScopes(refreshToken, Set.of("storage.write:/"));
    checkAccessTokenScopes(accessToken, NO_SCOPES);

    accessToken = refreshTokenWithScopes(refreshToken, Set.of("openid storage.read:/another/path"));
    checkAccessTokenScopes(accessToken, Set.of("openid"));

    scopePolicyRepo.delete(denyAllPolicy);
    scopePolicyRepo.delete(allowUserWithPathPolicy);
  }

  private ValidatableResponse authorizationCodeFlow(String clientId, String clientSecret,
      String redirectUri, String username, String password, String scopes) {

    ValidatableResponse resp1 = RestAssured.given()
      .queryParam("response_type", "code")
      .queryParam("client_id", clientId)
      .queryParam("redirect_uri", redirectUri)
      .queryParam("scope", scopes)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .redirects()
      .follow(false)
      .when()
      .get(authorizeUrl)
      .then()
      .statusCode(HttpStatus.FOUND.value())
      .header("Location", is(loginUrl));

    RestAssured.given()
      .formParam("username", username)
      .formParam("password", password)
      .formParam("submit", "Login")
      .cookie(resp1.extract().detailedCookie("JSESSIONID"))
      .redirects()
      .follow(false)
      .when()
      .post(loginUrl)
      .then()
      .statusCode(HttpStatus.FOUND.value());

    RestAssured.given()
      .cookie(resp1.extract().detailedCookie("JSESSIONID"))
      .queryParam("response_type", "code")
      .queryParam("client_id", clientId)
      .queryParam("redirect_uri", redirectUri)
      .queryParam("scope", scopes)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .redirects()
      .follow(false)
      .when()
      .get(authorizeUrl)
      .then()
      .log()
      .all()
      .statusCode(HttpStatus.OK.value());

    ValidatableResponse resp2 = RestAssured.given()
      .cookie(resp1.extract().detailedCookie("JSESSIONID"))
      .formParam("user_oauth_approval", "true")
      .formParam("authorize", "Authorize")
      .formParam("remember", "none")
      .redirects()
      .follow(false)
      .when()
      .post(authorizeUrl)
      .then()
      .statusCode(HttpStatus.SEE_OTHER.value());

    String authzCode = UriComponentsBuilder.fromHttpUrl(resp2.extract().header("Location"))
      .build()
      .getQueryParams()
      .get("code")
      .get(0);

    return RestAssured.given()
      .formParam("grant_type", "authorization_code")
      .formParam("redirect_uri", redirectUri)
      .formParam("code", authzCode)
      .formParam("state", "1")
      .auth()
      .preemptive()
      .basic(clientId, clientSecret)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());
  }

  private String refreshTokenWithScopes(String refreshToken, Set<String> requestedScopes)
      throws JsonMappingException, JsonProcessingException, ParseException {

    final String TEST_CLIENT_ID = "refresh-client";
    final String TEST_CLIENT_SECRET = "secret";

    ValidatableResponse response;

    if (requestedScopes.isEmpty()) {
      response = RestAssured.given()
        .formParam("grant_type", "refresh_token")
        .formParam("refresh_token", refreshToken)
        .auth()
        .preemptive()
        .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
        .when()
        .post(tokenUrl)
        .then()
        .statusCode(HttpStatus.OK.value());
    } else {
      response = RestAssured.given()
        .formParam("grant_type", "refresh_token")
        .formParam("refresh_token", refreshToken)
        .formParam("scope", Joiner.on(" ").join(requestedScopes))
        .auth()
        .preemptive()
        .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
        .when()
        .post(tokenUrl)
        .then()
        .statusCode(HttpStatus.OK.value());
    }

    String responseAsString = response.extract().body().asString();
    return mapper.readTree(responseAsString).get("access_token").asText();
  }

  private void checkAccessTokenScopes(String accessToken, Set<String> expectedScopes)
      throws ParseException {

    SignedJWT token = SignedJWT.parse(accessToken);

    if (expectedScopes.isEmpty()) {
      assertNull(token.getJWTClaimsSet().getStringClaim("scope"));
      return;
    }
    List<String> scopes = Arrays.asList(token.getJWTClaimsSet().getStringClaim("scope").split(" "));

    assertThat(scopes.size(), is(expectedScopes.size()));
    expectedScopes.forEach(s -> {
      assertTrue(scopes.contains(s));
    });
  }
}
