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
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import io.restassured.RestAssured;
import io.restassured.http.Cookie;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
@TestPropertySource(properties = {"iam.access_token.include_scope=true"})
@ActiveProfiles({"h2-test", "h2", "wlcg-scopes"})
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

  IamAccount findTestAccount() {
    return accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found!"));
  }

  private ValidatableResponse getTokenResponseWithAudience(String resourceParamAuthz,
      String resourceParamToken, String resourceValueAuthz, String resourceValueToken) {

    ValidatableResponse resp1 = RestAssured.given()
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam(resourceParamAuthz, resourceValueAuthz)
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
      .formParam("username", TEST_USER_NAME)
      .formParam("password", TEST_USER_PASSWORD)
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
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam(resourceParamAuthz, resourceValueAuthz)
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
      .formParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .formParam("code", authzCode)
      .formParam("state", "1")
      .formParam(resourceParamToken, resourceValueToken)
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());
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
  public void testAuthzCodeAudienceSupport() throws IOException, ParseException {

    String[] audienceKeys = {"aud", "audience"};

    for (String audKey : audienceKeys) {

      ValidatableResponse resp1 = RestAssured.given()
        .queryParam("response_type", RESPONSE_TYPE_CODE)
        .queryParam("client_id", TEST_CLIENT_ID)
        .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .queryParam("scope", SCOPE)
        .queryParam(audKey, "example-audience")
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
        .formParam("username", TEST_USER_NAME)
        .formParam("password", TEST_USER_PASSWORD)
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
        .queryParam("response_type", RESPONSE_TYPE_CODE)
        .queryParam("client_id", TEST_CLIENT_ID)
        .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .queryParam("scope", SCOPE)
        .queryParam(audKey, "example-audience")
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

      ValidatableResponse resp3 = RestAssured.given()
        .formParam("grant_type", "authorization_code")
        .formParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .formParam("code", authzCode)
        .formParam("state", "1")
        .auth()
        .preemptive()
        .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
        .when()
        .post(tokenUrl)
        .then()
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
  public void testAuthzCodeResourceIndicatorSupport() throws IOException, ParseException {

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
  public void testAuthzCodeResourceIndicatorNotOriginallyGranted() {

    ValidatableResponse resp1 = RestAssured.given()
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
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
      .statusCode(HttpStatus.FOUND.value())
      .header("Location", is(loginUrl));

    RestAssured.given()
      .formParam("username", TEST_USER_NAME)
      .formParam("password", TEST_USER_PASSWORD)
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
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
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

    RestAssured.given()
      .formParam("grant_type", "authorization_code")
      .formParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .formParam("code", authzCode)
      .formParam("state", "1")
      .formParam("resource", "http://example3.org")
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .assertThat()
      .body("error", equalTo("invalid_target"))
      .assertThat()
      .body("error_description", equalTo("The requested resource was not originally granted"));

  }

  @Test
  public void testNarrowerResourceIndicator() throws IOException, ParseException {

    ValidatableResponse tokenEndpointResp = getTokenResponseWithAudience("resource", "resource",
        "http://example1.org http://example2.org", "http://example1.org");

    String accessToken =
        mapper.readTree(tokenEndpointResp.extract().body().asString()).get("access_token").asText();
    JWT atJwt = JWTParser.parse(accessToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://example1.org"));

  }

  @Test
  public void testFilteredResourceIndicator() throws IOException, ParseException {

    ValidatableResponse tokenEndpointResp = getTokenResponseWithAudience("resource", "resource",
        "http://storm.org http://dcache.org", "http://storm.org http://rucio.org");

    String accessToken =
        mapper.readTree(tokenEndpointResp.extract().body().asString()).get("access_token").asText();
    JWT atJwt = JWTParser.parse(accessToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://storm.org"));

  }

  @Test
  public void testFilteredResourceIndicatorWithAudRequest() throws IOException, ParseException {

    ValidatableResponse tokenEndpointResp = getTokenResponseWithAudience("resource", "audience",
        "http://1.org http://2.org", "http://1.org http://3.org");

    String accessToken =
        mapper.readTree(tokenEndpointResp.extract().body().asString()).get("access_token").asText();
    JWT atJwt = JWTParser.parse(accessToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://1.org"));

  }

  @Test
  public void testAuthzCodeEmptyResourceIndicator() throws IOException, ParseException {

    ValidatableResponse resp1 = RestAssured.given()
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
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
      .statusCode(HttpStatus.FOUND.value())
      .header("Location", is(loginUrl));

    RestAssured.given()
      .formParam("username", TEST_USER_NAME)
      .formParam("password", TEST_USER_PASSWORD)
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
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
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

    ValidatableResponse resp3 = RestAssured.given()
      .formParam("grant_type", "authorization_code")
      .formParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .formParam("code", authzCode)
      .formParam("state", "1")
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());

    String accessToken =
        mapper.readTree(resp3.extract().body().asString()).get("access_token").asText();
    JWT atJwt = JWTParser.parse(accessToken);

    assertNotNull(atJwt.getJWTClaimsSet().getAudience());
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(2));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://example1.org"));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://example2.org"));

  }

  @Test
  public void testRefreshTokenAfterAuthzCodeWorks() throws IOException {

    refreshTokenRepository.deleteAll();

    ValidatableResponse resp1 = RestAssured.given()
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
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
      .formParam("username", TEST_USER_NAME)
      .formParam("password", TEST_USER_PASSWORD)
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
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
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

    ValidatableResponse resp3 = RestAssured.given()
      .formParam("grant_type", "authorization_code")
      .formParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .formParam("code", authzCode)
      .formParam("state", "1")
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());

    List<OAuth2RefreshTokenEntity> refreshTokens = refreshTokenRepository
      .findValidRefreshTokensForUserAndClient(TEST_USER_NAME, TEST_CLIENT_ID, new Date(),
          Pageable.unpaged())
      .getContent();
    assertThat(refreshTokens, hasSize(1));
    assertThat(refreshTokens.get(0).getAuthenticationHolder().getScope(),
        not(hasItems("iam:admin.read", "iam:admin.write", "scim:read", "scim:write")));

    String refreshToken =
        mapper.readTree(resp3.extract().body().asString()).get("refresh_token").asText();

    ValidatableResponse resp4 = RestAssured.given()
      .formParam("grant_type", "refresh_token")
      .formParam("refresh_token", refreshToken)
      .formParam("scope", "openid")
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());

    String refreshedToken =
        mapper.readTree(resp4.extract().body().asString()).get("access_token").asText();

    verifyForbiddenEndpointsForTestUserWithToken(refreshedToken);

    RestAssured.given()
      .formParam("grant_type", "refresh_token")
      .formParam("refresh_token", refreshToken)
      .formParam("scope", "openid iam:admin.read iam:admin.write")
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body("error", equalTo("invalid_scope"))
      .body("error_description", equalTo("Up-scoping is not allowed."));

    RestAssured.given()
      .formParam("grant_type", "refresh_token")
      .formParam("refresh_token", refreshToken)
      .formParam("scope", "openid scim:read scim:write")
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body("error", equalTo("invalid_scope"))
      .body("error_description", equalTo("Up-scoping is not allowed."));

    ValidatableResponse resp7 = RestAssured.given()
      .formParam("grant_type", "refresh_token")
      .formParam("refresh_token", refreshToken)
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());

    refreshedToken =
        mapper.readTree(resp7.extract().body().asString()).get("access_token").asText();

    verifyForbiddenEndpointsForTestUserWithToken(refreshedToken);

  }

  @Test
  public void testNarrowerResourceIndicatorRTFlowAfterAuthzCode()
      throws IOException, ParseException {

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
  public void testFilteredResourceIndicatorRTFlowAfterAuthzCode()
      throws IOException, ParseException {

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
  public void testFilteredResourceIndicatorWithAudRequestRTFlowAfterAuthzCode()
      throws IOException, ParseException {

    refreshTokenRepository.deleteAll();

    Cookie session = getSession(
        authorize(null, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, TEST_FULL_RESOURCE)
          .statusCode(HttpStatus.FOUND.value())
          .header("Location", is(loginUrl)));
    login(session, TEST_USER_NAME, TEST_USER_PASSWORD);
    authorize(session, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, TEST_FULL_RESOURCE)
      .statusCode(HttpStatus.OK.value());
    String authzCode = approve(session);
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
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());

    String refreshedToken =
        mapper.readTree(refreshResponse.extract().body().asString()).get("access_token").asText();

    JWT atJwt = JWTParser.parse(refreshedToken);

    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://example1.org"));

  }

  @Test
  public void testResourceIndicatorRTFlowBoundToAuthzCode() throws IOException, ParseException {

    refreshTokenRepository.deleteAll();

    Cookie session = getSession(
        authorize(null, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, TEST_FULL_RESOURCE)
          .statusCode(HttpStatus.FOUND.value())
          .header("Location", is(loginUrl)));
    login(session, TEST_USER_NAME, TEST_USER_PASSWORD);
    authorize(session, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, TEST_FULL_RESOURCE)
      .statusCode(HttpStatus.OK.value());
    String authzCode = approve(session);
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
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://example1.org"));
    assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("http://example2.org"));

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
      .get("/scim/Users/80e5fb8d-b7c8-451a-89ba-346ae278a66f")
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
  public void testNullAuthorizationCode() throws IOException {

    Cookie session =
        getSession(authorize(null, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, null)
          .statusCode(HttpStatus.FOUND.value())
          .header("Location", is(loginUrl)));
    login(session, TEST_USER_NAME, TEST_USER_PASSWORD);
    authorize(session, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, null)
      .statusCode(HttpStatus.OK.value());
    approve(session);
    ValidatableResponse tokenResponse =
        token(null, TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
          .statusCode(HttpStatus.BAD_REQUEST.value());

    String error = mapper.readTree(tokenResponse.extract().body().asString()).get("error").asText();
    String errorMessage = mapper.readTree(tokenResponse.extract().body().asString())
      .get("error_description")
      .asText();

    assertEquals("invalid_request", error);
    assertEquals("An authorization code must be supplied.", errorMessage);

  }

  @Test
  public void testFakeAuthorizationCode() throws IOException {

    Cookie session =
        getSession(authorize(null, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, null)
          .statusCode(HttpStatus.FOUND.value())
          .header("Location", is(loginUrl)));
    login(session, TEST_USER_NAME, TEST_USER_PASSWORD);
    authorize(session, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, null)
      .statusCode(HttpStatus.OK.value());
    approve(session);
    ValidatableResponse tokenResponse =
        token("1234", TEST_CLIENT_REDIRECT_URI, TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
          .statusCode(HttpStatus.BAD_REQUEST.value());

    String error = mapper.readTree(tokenResponse.extract().body().asString()).get("error").asText();
    String errorMessage = mapper.readTree(tokenResponse.extract().body().asString())
      .get("error_description")
      .asText();

    assertEquals("invalid_grant", error);
    assertEquals("JpaAuthorizationCodeRepository: no authorization code found for value 1234",
        errorMessage);
  }

  @Test
  public void testRedirectURIMismatch() throws IOException {

    Cookie session =
        getSession(authorize(null, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, null)
          .statusCode(HttpStatus.FOUND.value())
          .header("Location", is(loginUrl)));
    login(session, TEST_USER_NAME, TEST_USER_PASSWORD);
    authorize(session, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, null)
      .statusCode(HttpStatus.OK.value());
    String authzCode = approve(session);
    ValidatableResponse tokenResponse =
        token(authzCode, "http://fake.redirect.uri.org", TEST_CLIENT_ID, TEST_CLIENT_SECRET, null)
          .statusCode(HttpStatus.BAD_REQUEST.value());

    String error = mapper.readTree(tokenResponse.extract().body().asString()).get("error").asText();
    String errorMessage = mapper.readTree(tokenResponse.extract().body().asString())
      .get("error_description")
      .asText();

    assertEquals("invalid_grant", error);
    assertEquals("Redirect URI mismatch.", errorMessage);

  }

  @Test
  public void testClientIDMismatch() throws IOException {

    Cookie session =
        getSession(authorize(null, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, null)
          .statusCode(HttpStatus.FOUND.value())
          .header("Location", is(loginUrl)));
    login(session, TEST_USER_NAME, TEST_USER_PASSWORD);
    authorize(session, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, null)
      .statusCode(HttpStatus.OK.value());
    String authzCode = approve(session);
    ValidatableResponse tokenResponse = RestAssured.given()
      .formParam("grant_type", "authorization_code")
      .formParam("client_id", "fake-client-id")
      .formParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .formParam("code", authzCode)
      .formParam("state", "1")
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.UNAUTHORIZED.value());

    String error = mapper.readTree(tokenResponse.extract().body().asString()).get("error").asText();
    String errorMessage = mapper.readTree(tokenResponse.extract().body().asString())
      .get("error_description")
      .asText();

    assertEquals("invalid_client", error);
    assertEquals("Given client ID does not match authenticated client", errorMessage);
  }

  @Test
  public void testUnverifiedUserCannotGetAToken() {

    Cookie session =
        getSession(authorize(null, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, null)
          .statusCode(HttpStatus.FOUND.value())
          .header("Location", is(loginUrl)));
    login(session, "unverified-user", "password");
    authorize(session, TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, SCOPE, null)
      .statusCode(HttpStatus.FORBIDDEN.value());
  }

  private ValidatableResponse authorize(Cookie cookie, String clientId, String redirectUri,
      String scope, String resource) {

    RequestSpecification request = RestAssured.given();
    if (cookie != null) {
      request.cookie(cookie);
    }
    if (clientId != null) {
      request.queryParam("client_id", clientId);
    }
    if (redirectUri != null) {
      request.queryParam("redirect_uri", redirectUri);
    }
    if (scope != null) {
      request.queryParam("scope", scope);
    }
    if (resource != null) {
      request.queryParam("resource", resource);
    }
    request.queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("nonce", "1")
      .queryParam("state", "1");
    return request.redirects().follow(false).when().get(authorizeUrl).then();
  }

  private Cookie getSession(ValidatableResponse authorizeResponse) {

    return authorizeResponse.extract().detailedCookie("JSESSIONID");
  }

  private ValidatableResponse login(Cookie cookie, String username, String password) {

    return RestAssured.given()
      .formParam("username", username)
      .formParam("password", password)
      .formParam("submit", "Login")
      .cookie(cookie)
      .redirects()
      .follow(false)
      .when()
      .post(loginUrl)
      .then();
  }

  private String approve(Cookie cookie) {
    ValidatableResponse response = RestAssured.given()
      .cookie(cookie)
      .formParam("user_oauth_approval", "true")
      .formParam("authorize", "Authorize")
      .formParam("remember", "none")
      .redirects()
      .follow(false)
      .when()
      .post(authorizeUrl)
      .then()
      .statusCode(HttpStatus.SEE_OTHER.value());
    return UriComponentsBuilder.fromHttpUrl(response.extract().header("Location"))
      .build()
      .getQueryParams()
      .get("code")
      .get(0);
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
}
