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
import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
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

      // @formatter:off
      ValidatableResponse resp1 = RestAssured.given()
        .queryParam("response_type", RESPONSE_TYPE_CODE)
        .queryParam("client_id", TEST_CLIENT_ID)
        .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .queryParam("scope", SCOPE)
        .queryParam(audKey, "example-audience")
        .queryParam("nonce", "1")
        .queryParam("state", "1")
        .redirects().follow(false)
      .when()
        .get(authorizeUrl)
      .then()
        .statusCode(HttpStatus.FOUND.value())
        .header("Location", is(loginUrl));
      // @formatter:on

      // @formatter:off
      RestAssured.given()
        .formParam("username", TEST_USER_NAME)
        .formParam("password", TEST_USER_PASSWORD)
        .formParam("submit", "Login")
        .cookie(resp1.extract().detailedCookie("JSESSIONID"))
        .redirects().follow(false)
      .when()
        .post(loginUrl)
      .then()
        .statusCode(HttpStatus.FOUND.value());
      // @formatter:on

      // @formatter:off
      RestAssured.given()
        .cookie(resp1.extract().detailedCookie("JSESSIONID"))
        .queryParam("response_type", RESPONSE_TYPE_CODE)
        .queryParam("client_id", TEST_CLIENT_ID)
        .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .queryParam("scope", SCOPE)
        .queryParam(audKey, "example-audience")
        .queryParam("nonce", "1")
        .queryParam("state", "1")
        .redirects().follow(false)
      .when()
        .get(authorizeUrl)
      .then()
        .log().all()
        .statusCode(HttpStatus.OK.value());
      // @formatter:on

      // @formatter:off
      ValidatableResponse resp2 = RestAssured.given()
        .cookie(resp1.extract().detailedCookie("JSESSIONID"))
        .formParam("user_oauth_approval", "true")
        .formParam("authorize", "Authorize")
        .formParam("remember", "none")
        .redirects().follow(false)
      .when()
        .post(authorizeUrl)
      .then()
        .statusCode(HttpStatus.SEE_OTHER.value());
      // @formatter:on

      String authzCode = UriComponentsBuilder.fromHttpUrl(resp2.extract().header("Location"))
        .build()
        .getQueryParams()
        .get("code")
        .get(0);

      // @formatter:off
      ValidatableResponse resp3= RestAssured.given()
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
      // @formatter:on

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

}
