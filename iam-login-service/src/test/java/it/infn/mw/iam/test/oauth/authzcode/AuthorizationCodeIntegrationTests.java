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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.oauth.utils.OAuthBrowser;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {"iam.access_token.include_scope=true"})
@ActiveProfiles({"h2-test", "wlcg-scopes"})
public class AuthorizationCodeIntegrationTests extends ScopePolicyTestUtils {

  public static final String TEST_CLIENT_ID = "client";
  public static final String TEST_CLIENT_SECRET = "secret";
  public static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  public static final String LOCALHOST_URL_TEMPLATE = "http://localhost:%d";

  public static final String RESPONSE_TYPE_CODE = "code";

  public static final String SCOPE =
      "openid profile scim:read scim:write offline_access iam:admin.read iam:admin.write";

  public static final String TEST_USER_NAME = "test";
  public static final String TEST_USER_PASSWORD = "password";

  public static final String TEST_RESOURCE_1 = "http://example1.org";
  public static final String TEST_RESOURCE_2 = "http://example2.org";
  public static final String TEST_FULL_RESOURCE = TEST_RESOURCE_1 + " " + TEST_RESOURCE_2;

  private String loginUrl;
  private String authorizeUrl;
  private String tokenUrl;

  @Value("${local.server.port}")
  private Integer iamPort;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  private IamOAuthRefreshTokenRepository refreshTokenRepository;

  @Autowired
  private IamAccountRepository accountRepo;

  private String obtainAuthorizationCode(Map<String, String> extraParameters) {
    OAuthBrowser browser = new OAuthBrowser(String.format(LOCALHOST_URL_TEMPLATE, iamPort));

    Map<String, Object> parameters = new HashMap<>();
    parameters.put("response_type", RESPONSE_TYPE_CODE);
    parameters.put("client_id", TEST_CLIENT_ID);
    parameters.put("redirect_uri", TEST_CLIENT_REDIRECT_URI);
    parameters.put("scope", SCOPE);
    parameters.put("nonce", "1");
    parameters.put("state", "1");
    parameters.putAll(extraParameters);

    browser.authorize(parameters)
      .statusCode(HttpStatus.FOUND.value())
      .header("Location", is(loginUrl));

    browser.login(TEST_USER_NAME, TEST_USER_PASSWORD).statusCode(HttpStatus.FOUND.value());

    ValidatableResponse consentPage =
        browser.authorize(parameters).statusCode(HttpStatus.OK.value());

    return browser.approve(consentPage);
  }

  IamAccount findTestAccount() {
    return accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found!"));
  }

  private ValidatableResponse getTokenResponseWithAudience(String resourceParamAuthz,
      String resourceParamToken, String resourceValueAuthz, String resourceValueToken) {

    String code = obtainAuthorizationCode(Map.of(resourceParamAuthz, resourceValueAuthz));

    return RestAssured.given()
      .formParam("grant_type", "authorization_code")
      .formParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .formParam("code", code)
      .formParam("state", "1")
      .formParam(resourceParamToken, resourceValueToken)
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .redirects()
      .follow(false)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());
  }

  @BeforeAll
  static void init() {
    TestUtils.initRestAssured();
  }

  @BeforeEach
  void setup() {
    RestAssured.port = iamPort;
    loginUrl = String.format(LOCALHOST_URL_TEMPLATE + "/login", iamPort);
    authorizeUrl = String.format(LOCALHOST_URL_TEMPLATE + "/authorize", iamPort);
    tokenUrl = String.format(LOCALHOST_URL_TEMPLATE + "/token", iamPort);
  }

  @Test
  void testAuthzCodeMissingClientId() {

    RestAssured.given()
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("resource", "http://example1.org http://example2.org")
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .redirects()
      .follow(false)
      .when()
      .get(authorizeUrl)
      .then()
      .statusCode(HttpStatus.UNAUTHORIZED.value());
  }

  @Test
  void testAuthzCodeSupportsClaimsRequestParameter() {

    RestAssured.given()
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("claims", "email")
      .queryParam("resource", "http://example1.org http://example2.org")
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .redirects()
      .follow(false)
      .when()
      .get(authorizeUrl)
      .then()
      .statusCode(HttpStatus.FOUND.value())
      .header("Location", is(loginUrl));
  }

  @Test
  void testAuthzCodeAudienceSupport() throws Exception {

    String[] audienceKeys = {"aud", "audience"};

    for (String audKey : audienceKeys) {

      String code = obtainAuthorizationCode(Map.of(audKey, "example-audience"));

      ValidatableResponse resp3 =
          token(code, TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
            .statusCode(HttpStatus.OK.value());

      String accessToken =
          mapper.readTree(resp3.extract().body().asString()).get("access_token").asText();

      String idToken = mapper.readTree(resp3.extract().body().asString()).get("id_token").asText();

      JWT atJwt = JWTParser.parse(accessToken);
      JWT itJwt = JWTParser.parse(idToken);

      assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
      assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("example-audience"));

      assertThat(itJwt.getJWTClaimsSet().getAudience(), hasSize(1));
      assertThat(itJwt.getJWTClaimsSet().getAudience(), hasItem(TEST_CLIENT_ID));
    }

  }

  @Test
  void testAuthzCodeResourceIndicatorSupport() throws IOException, ParseException {

    ValidatableResponse tokenEndpointResp = getTokenResponseWithAudience("resource", "resource",
        "http://example1.org http://example2.org", "http://example1.org http://example2.org");

    String accessToken =
        mapper.readTree(tokenEndpointResp.extract().body().asString()).get("access_token").asText();
    JWT atJwt = JWTParser.parse(accessToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(2));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://example1.org"));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://example2.org"));

  }

  @Test
  void testAuthzCodeResourceIndicatorNotOriginallyGranted() {
    String code = obtainAuthorizationCode(Map.of("resource", TEST_FULL_RESOURCE));

    token(code, TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, "http://example3.org")
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body("error", equalTo("invalid_target"))
      .body("error_description", equalTo("The requested resource was not originally granted"));
  }

  @Test
  void testNarrowerResourceIndicator() throws Exception {

    ValidatableResponse tokenEndpointResp = getTokenResponseWithAudience("resource", "resource",
        "http://example1.org http://example2.org", "http://example1.org");

    String accessToken =
        mapper.readTree(tokenEndpointResp.extract().body().asString()).get("access_token").asText();
    JWT atJwt = JWTParser.parse(accessToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://example1.org"));
  }

  @Test
  void testFilteredResourceIndicator() throws Exception {

    ValidatableResponse tokenEndpointResp = getTokenResponseWithAudience("resource", "resource",
        "http://storm.org http://dcache.org", "http://storm.org http://rucio.org");

    String accessToken =
        mapper.readTree(tokenEndpointResp.extract().body().asString()).get("access_token").asText();
    JWT atJwt = JWTParser.parse(accessToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://storm.org"));
  }

  @Test
  void testFilteredResourceIndicatorWithAudRequest() throws Exception {

    ValidatableResponse tokenEndpointResp = getTokenResponseWithAudience("resource", "audience",
        "http://1.org http://2.org", "http://1.org http://3.org");

    String accessToken =
        mapper.readTree(tokenEndpointResp.extract().body().asString()).get("access_token").asText();
    JWT atJwt = JWTParser.parse(accessToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://1.org"));
  }

  @Test
  void testAuthzCodeEmptyResourceIndicator() throws IOException, ParseException {

    String authzCode = obtainAuthorizationCode(Map.of("resource", TEST_FULL_RESOURCE));

    ValidatableResponse tokenResponse =
        token(authzCode, TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
          .statusCode(HttpStatus.OK.value());

    String accessToken =
        mapper.readTree(tokenResponse.extract().body().asString()).get("access_token").asText();

    JWT atJwt = JWTParser.parse(accessToken);

    assertNotNull(atJwt.getJWTClaimsSet().getAudience());
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(2));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem(TEST_RESOURCE_1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem(TEST_RESOURCE_2));
  }

  @Test
  void testRefreshTokenAfterAuthzCodeWorks() throws IOException {
    refreshTokenRepository.deleteAll();

    String authzCode = obtainAuthorizationCode(Map.of());

    ValidatableResponse tokenResponse =
        token(authzCode, TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
          .statusCode(HttpStatus.OK.value());

    List<OAuth2RefreshTokenEntity> refreshTokens = refreshTokenRepository
      .findValidRefreshTokensForUserAndClient(TEST_USER_NAME, TEST_CLIENT_ID, new Date(),
          Pageable.unpaged())
      .getContent();

    assertThat(refreshTokens, hasSize(1));

    var grantedScopes = refreshTokens.get(0).getAuthenticationHolder().getScope();

    for (String forbiddenScope : List.of("iam:admin.read", "iam:admin.write", "scim:read",
        "scim:write")) {
      assertThat(grantedScopes, not(hasItem(forbiddenScope)));
    }

    String refreshToken =
        mapper.readTree(tokenResponse.extract().body().asString()).get("refresh_token").asText();

    // Refresh with a narrower scope.
    ValidatableResponse narrowedResponse =
        refresh(refreshToken, "openid", null, TEST_CLIENT_ID, TEST_CLIENT_SECRET)
          .statusCode(HttpStatus.OK.value());

    String narrowedAccessToken =
        mapper.readTree(narrowedResponse.extract().body().asString()).get("access_token").asText();

    verifyForbiddenEndpointsForTestUserWithToken(narrowedAccessToken);

    // Reject attempts to request scopes that were not granted.
    refresh(refreshToken, "openid iam:admin.read iam:admin.write", null, TEST_CLIENT_ID,
        TEST_CLIENT_SECRET).statusCode(HttpStatus.BAD_REQUEST.value())
          .body("error", equalTo("invalid_scope"))
          .body("error_description", equalTo("Up-scoping is not allowed."));

    refresh(refreshToken, "openid scim:read scim:write", null, TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body("error", equalTo("invalid_scope"))
      .body("error_description", equalTo("Up-scoping is not allowed."));

    // Refresh without explicitly requesting a scope.
    ValidatableResponse defaultScopeResponse =
        refresh(refreshToken, null, null, TEST_CLIENT_ID, TEST_CLIENT_SECRET)
          .statusCode(HttpStatus.OK.value());

    String defaultScopeAccessToken =
        mapper.readTree(defaultScopeResponse.extract().body().asString())
          .get("access_token")
          .asText();

    verifyForbiddenEndpointsForTestUserWithToken(defaultScopeAccessToken);
  }

  @Test
  void testNarrowerResourceIndicatorRTFlowAfterAuthzCode() throws IOException, ParseException {

    refreshTokenRepository.deleteAll();

    String resourceParam = "resource";
    String resourceValue = "http://example1.org http://example2.org";

    ValidatableResponse tokenEndpointResp =
        getTokenResponseWithAudience(resourceParam, resourceParam, resourceValue, resourceValue);

    String refreshToken = mapper.readTree(tokenEndpointResp.extract().body().asString())
      .get("refresh_token")
      .asText();

    ValidatableResponse resp1 = RestAssured.given()
      .formParam("grant_type", "refresh_token")
      .formParam("refresh_token", refreshToken)
      .formParam("scope", "openid")
      .formParam("resource", "http://example1.org")
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());

    String refreshedToken =
        mapper.readTree(resp1.extract().body().asString()).get("access_token").asText();

    JWT atJwt = JWTParser.parse(refreshedToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://example1.org"));

  }

  @Test
  void testFilteredResourceIndicatorRTFlowAfterAuthzCode() throws IOException, ParseException {

    refreshTokenRepository.deleteAll();

    String resourceParam = "resource";
    String resourceValue = "http://example1.org http://example2.org";

    ValidatableResponse tokenEndpointResp =
        getTokenResponseWithAudience(resourceParam, resourceParam, resourceValue, resourceValue);

    String refreshToken = mapper.readTree(tokenEndpointResp.extract().body().asString())
      .get("refresh_token")
      .asText();

    ValidatableResponse resp1 = RestAssured.given()
      .formParam("grant_type", "refresh_token")
      .formParam("refresh_token", refreshToken)
      .formParam("scope", "openid")
      .formParam("resource", "http://example1.org http://example3.org")
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());

    String refreshedToken =
        mapper.readTree(resp1.extract().body().asString()).get("access_token").asText();

    JWT atJwt = JWTParser.parse(refreshedToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://example1.org"));
  }

  @Test
  void testFilteredResourceIndicatorWithAudRequestRTFlowAfterAuthzCode()
      throws IOException, ParseException {

    refreshTokenRepository.deleteAll();

    String authzCode = obtainAuthorizationCode(Map.of("resource", TEST_FULL_RESOURCE));

    ValidatableResponse tokenResponse =
        token(authzCode, TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
          .statusCode(HttpStatus.OK.value());

    String refreshToken =
        mapper.readTree(tokenResponse.extract().body().asString()).get("refresh_token").asText();

    ValidatableResponse refreshResponse = RestAssured.given()
      .formParam("grant_type", "refresh_token")
      .formParam("refresh_token", refreshToken)
      .formParam("scope", "openid")
      .formParam("audience", "http://example1.org http://example3.org")
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .redirects()
      .follow(false)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());

    String refreshedToken =
        mapper.readTree(refreshResponse.extract().body().asString()).get("access_token").asText();

    JWT atJwt = JWTParser.parse(refreshedToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem(TEST_RESOURCE_1));
  }

  @Test
  void testResourceIndicatorRTFlowBoundToAuthzCode() throws IOException, ParseException {

    refreshTokenRepository.deleteAll();

    String authzCode = obtainAuthorizationCode(Map.of("resource", TEST_FULL_RESOURCE));

    ValidatableResponse tokenResponse =
        token(authzCode, TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
          .statusCode(HttpStatus.OK.value());

    String refreshToken =
        mapper.readTree(tokenResponse.extract().body().asString()).get("refresh_token").asText();

    ValidatableResponse refreshResponse =
        refresh(refreshToken, "openid", TEST_FULL_RESOURCE, TEST_CLIENT_ID, TEST_CLIENT_SECRET)
          .statusCode(HttpStatus.OK.value());

    String refreshedToken =
        mapper.readTree(refreshResponse.extract().body().asString()).get("access_token").asText();

    JWT atJwt = JWTParser.parse(refreshedToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(2));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem(TEST_RESOURCE_1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem(TEST_RESOURCE_2));
  }

  private void verifyForbiddenEndpointsForTestUserWithToken(String token) {

    RestAssured.given()
      .header("Authorization", "Bearer " + token)
      .when()
      .get("/scim/Users")
      .then()
      .statusCode(HttpStatus.FORBIDDEN.value());

    RestAssured.given()
      .header("Authorization", "Bearer " + token)
      .when()
      .get("/scim/Groups")
      .then()
      .statusCode(HttpStatus.FORBIDDEN.value());

    RestAssured.given()
      .header("Authorization", "Bearer " + token)
      .when()
      .get("/scim/Users/f2ce8cb2-a1db-4884-9ef0-d8842cc02b4a")
      .then()
      .statusCode(HttpStatus.FORBIDDEN.value());

    RestAssured.given()
      .header("Authorization", "Bearer " + token)
      .when()
      .get("/scim/Groups/c617d586-54e6-411d-8e38-649677980001")
      .then()
      .statusCode(HttpStatus.FORBIDDEN.value());

    RestAssured.given()
      .header("Authorization", "Bearer " + token)
      .when()
      .delete("/scim/Users/80e5fb8d-b7c8-451a-89ba-346ae278a66f")
      .then()
      .statusCode(HttpStatus.FORBIDDEN.value());

    RestAssured.given()
      .header("Authorization", "Bearer " + token)
      .when()
      .delete("/scim/Groups/c617d586-54e6-411d-8e38-649677980001")
      .then()
      .statusCode(HttpStatus.FORBIDDEN.value());

    RestAssured.given()
      .header("Authorization", "Bearer " + token)
      .when()
      .get("/iam/group/c617d586-54e6-411d-8e38-649677980001/attributes")
      .then()
      .statusCode(HttpStatus.FORBIDDEN.value());

    RestAssured.given()
      .header("Authorization", "Bearer " + token)
      .when()
      .get("/iam/account/80e5fb8d-b7c8-451a-89ba-346ae278a66f/authorities")
      .then()
      .statusCode(HttpStatus.FORBIDDEN.value());

    RestAssured.given()
      .header("Authorization", "Bearer " + token)
      .when()
      .get("/iam/api/clients")
      .then()
      .statusCode(HttpStatus.FORBIDDEN.value());

    RestAssured.given()
      .header("Authorization", "Bearer " + token)
      .when()
      .get("/iam/scope_policies")
      .then()
      .statusCode(HttpStatus.FORBIDDEN.value());

  }

  @Test
  void testNullAuthorizationCode() throws IOException {
    ValidatableResponse tokenResponse =
        token(null, TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
          .statusCode(HttpStatus.BAD_REQUEST.value());

    var responseBody = mapper.readTree(tokenResponse.extract().body().asString());

    assertEquals("invalid_request", responseBody.get("error").asText());
    assertEquals("An authorization code must be supplied.",
        responseBody.get("error_description").asText());
  }

  @Test
  void testFakeAuthorizationCode() throws IOException {
    ValidatableResponse tokenResponse =
        token("1234", TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
          .statusCode(HttpStatus.BAD_REQUEST.value());

    var responseBody = mapper.readTree(tokenResponse.extract().body().asString());

    assertEquals("invalid_grant", responseBody.get("error").asText());
    assertEquals("JpaAuthorizationCodeRepository: no authorization code found for value 1234",
        responseBody.get("error_description").asText());
  }

  @Test
  void testRedirectURIMismatch() throws IOException {
    String authzCode = obtainAuthorizationCode(Map.of());

    ValidatableResponse tokenResponse =
        token(authzCode, "http://fake.redirect.uri.org", TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
          .statusCode(HttpStatus.BAD_REQUEST.value());

    var responseBody = mapper.readTree(tokenResponse.extract().body().asString());

    assertEquals("invalid_grant", responseBody.get("error").asText());
    assertEquals("Redirect URI mismatch.", responseBody.get("error_description").asText());
  }

  @Test
  void testClientIDMismatch() throws IOException {
    String authzCode = obtainAuthorizationCode(Map.of());

    ValidatableResponse tokenResponse = RestAssured.given()
      .formParam("grant_type", "authorization_code")
      .formParam("client_id", "fake-client-id")
      .formParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .formParam("code", authzCode)
      .formParam("state", "1")
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .redirects()
      .follow(false)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.UNAUTHORIZED.value());

    var responseBody = mapper.readTree(tokenResponse.extract().body().asString());

    assertEquals("invalid_client", responseBody.get("error").asText());
    assertEquals("Given client ID does not match authenticated client",
        responseBody.get("error_description").asText());
  }

  @Test
  void testUnverifiedUserCannotGetAToken() {
    OAuthBrowser browser = new OAuthBrowser(String.format(LOCALHOST_URL_TEMPLATE, iamPort));

    Map<String, Object> parameters =
        Map.of("response_type", RESPONSE_TYPE_CODE, "client_id", TEST_CLIENT_ID, "redirect_uri",
            TEST_CLIENT_REDIRECT_URI, "scope", SCOPE, "nonce", "1", "state", "1");

    browser.authorize(parameters)
      .statusCode(HttpStatus.FOUND.value())
      .header("Location", is(loginUrl));

    browser.login("unverified-user", "password").statusCode(HttpStatus.FOUND.value());

    browser.authorize(parameters).statusCode(HttpStatus.FORBIDDEN.value());
  }

  private ValidatableResponse token(String code, String redirectUri, String clientId,
      String clientSecret, String resource) {

    RequestSpecification request = RestAssured.given();
    if (code != null) {
      request.formParam("code", code);
    }
    if (redirectUri != null) {
      request.formParam("redirect_uri", redirectUri);
    }
    if (resource != null) {
      request.formParam("resource", resource);
    }
    return request.formParam("grant_type", "authorization_code")
      .formParam("state", "1")
      .auth()
      .preemptive()
      .basic(clientId, clientSecret)
      .when()
      .post(tokenUrl)
      .then();
  }

  private ValidatableResponse refresh(String refreshToken, String scope, String resource,
      String clientId, String clientSecret) {

    RequestSpecification request = RestAssured.given();
    if (refreshToken != null) {
      request.formParam("refresh_token", refreshToken);
    }
    if (scope != null) {
      request.formParam("scope", scope);
    }
    if (resource != null) {
      request.formParam("resource", resource);
    }
    request.formParam("grant_type", "refresh_token");
    return request.auth().preemptive().basic(clientId, clientSecret).when().post(tokenUrl).then();
  }

  @Test
  void testUsingCodeTwiceIsBadRequest() {
    String code = obtainAuthorizationCode(Map.of());

    token(code, TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
      .statusCode(HttpStatus.OK.value());

    token(code, TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
      .statusCode(HttpStatus.BAD_REQUEST.value());
  }
}
