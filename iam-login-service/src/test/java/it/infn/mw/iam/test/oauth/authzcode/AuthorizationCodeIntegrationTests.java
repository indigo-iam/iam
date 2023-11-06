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

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

import java.io.IOException;
import java.text.ParseException;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
public class AuthorizationCodeIntegrationTests {

  @Value("${local.server.port}")
  private Integer iamPort;

  @Autowired
  ObjectMapper mapper;

  public static final String TEST_CLIENT_ID = "client";
  public static final String TEST_CLIENT_SECRET = "secret";
  public static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  public static final String LOCALHOST_URL_TEMPLATE = "http://localhost:%d";

  public static final String RESPONSE_TYPE_CODE = "code";

  public static final String SCOPE =
      "openid profile scim:read scim:write offline_access iam:admin.read iam:admin.write";

  public static final String TEST_USER_ID = "test";
  public static final String TEST_USER_PASSWORD = "password";

  private String loginUrl;
  private String authorizeUrl;
  private String tokenUrl;

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
  public void testAuthzCodeAudienceSupport()
      throws JsonProcessingException, IOException, ParseException {

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
      ValidatableResponse resp2 = RestAssured.given()
        .formParam("username", "test")
        .formParam("password", "password")
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
        .cookie(resp2.extract().detailedCookie("JSESSIONID"))
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
      ValidatableResponse resp4 = RestAssured.given()
        .cookie(resp2.extract().detailedCookie("JSESSIONID"))
        .formParam("user_oauth_approval", "true")
        .formParam("authorize", "Authorize")
        .formParam("scope_openid", "openid")
        .formParam("scope_profile", "profile")
        .formParam("remember", "none")
        .redirects().follow(false)
      .when()
        .post(authorizeUrl)
      .then()
        .statusCode(HttpStatus.SEE_OTHER.value());
      // @formatter:on

      String authzCode = UriComponentsBuilder.fromHttpUrl(resp4.extract().header("Location"))
        .build()
        .getQueryParams()
        .get("code")
        .get(0);

      // @formatter:off
      ValidatableResponse resp5= RestAssured.given()
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
          mapper.readTree(resp5.extract().body().asString()).get("access_token").asText();

      String idToken = mapper.readTree(resp5.extract().body().asString()).get("id_token").asText();

      JWT atJwt = JWTParser.parse(accessToken);
      JWT itJwt = JWTParser.parse(idToken);

      assertThat(atJwt.getJWTClaimsSet().getAudience(), hasSize(1));
      assertThat(atJwt.getJWTClaimsSet().getAudience(), hasItem("example-audience"));

      assertThat(itJwt.getJWTClaimsSet().getAudience(), hasSize(1));
      assertThat(itJwt.getJWTClaimsSet().getAudience(), hasItem(TEST_CLIENT_ID));
    }

  }

  @Test
  public void testRefreshTokenAfterAuthzCodeWorks()
      throws JsonProcessingException, IOException, ParseException {

    // @formatter:off
      ValidatableResponse resp1 = RestAssured.given()
        .queryParam("response_type", RESPONSE_TYPE_CODE)
        .queryParam("client_id", TEST_CLIENT_ID)
        .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .queryParam("scope", SCOPE)
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
      ValidatableResponse resp2 = RestAssured.given()
        .formParam("username", "test")
        .formParam("password", "password")
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
        .cookie(resp2.extract().detailedCookie("JSESSIONID"))
        .queryParam("response_type", RESPONSE_TYPE_CODE)
        .queryParam("client_id", TEST_CLIENT_ID)
        .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .queryParam("scope", SCOPE)
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
      ValidatableResponse resp4 = RestAssured.given()
        .cookie(resp2.extract().detailedCookie("JSESSIONID"))
        .formParam("user_oauth_approval", "true")
        .formParam("authorize", "Authorize")
        .formParam("scope_openid", "openid")
        .formParam("scope_profile", "profile")
        .formParam("scope_offline_access", "offline_access")
        .formParam("scope_scim_read", "scim:read")
        .formParam("scope_scim_write", "scim:write")
        .formParam("scope_iam_admin_read", "iam:admin.read")
        .formParam("scope_iam_admin_write", "iam:admin.write")
        .formParam("remember", "none")
        .redirects().follow(false)
      .when()
        .post(authorizeUrl)
      .then()
        .statusCode(HttpStatus.SEE_OTHER.value());
      // @formatter:on

    String authzCode = UriComponentsBuilder.fromHttpUrl(resp4.extract().header("Location"))
      .build()
      .getQueryParams()
      .get("code")
      .get(0);

    // @formatter:off
      ValidatableResponse resp5= RestAssured.given()
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

    String refreshToken =
        mapper.readTree(resp5.extract().body().asString()).get("refresh_token").asText();

    // @formatter:off
      ValidatableResponse resp6= RestAssured.given()
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
      // @formatter:on

    String refreshedToken =
        mapper.readTree(resp6.extract().body().asString()).get("access_token").asText();

   // @formatter:off
      RestAssured.given()
          .header("Authorization", "Bearer " + refreshedToken)
      .when()
        .get("/scim/Users")
      .then()
        .statusCode(HttpStatus.FORBIDDEN.value());
      
      RestAssured.given()
          .header("Authorization", "Bearer " + refreshedToken)
      .when()
          .get("/scim/Groups")
      .then()
          .statusCode(HttpStatus.FORBIDDEN.value());
      
      RestAssured.given()
          .header("Authorization", "Bearer " + refreshedToken)
      .when()
          .get("/scim/Users/80e5fb8d-b7c8-451a-89ba-346ae278a66f")
      .then()
          .statusCode(HttpStatus.FORBIDDEN.value());
      
      RestAssured.given()
          .header("Authorization", "Bearer " + refreshedToken)
      .when()
          .get("/scim/Groups/c617d586-54e6-411d-8e38-649677980001")
      .then()
          .statusCode(HttpStatus.FORBIDDEN.value());
      
      RestAssured.given()
          .header("Authorization", "Bearer " + refreshedToken)
      .when()
          .delete("/scim/Users/80e5fb8d-b7c8-451a-89ba-346ae278a66f")
      .then()
          .statusCode(HttpStatus.FORBIDDEN.value());
      
      RestAssured.given()
          .header("Authorization", "Bearer " + refreshedToken)
      .when()
          .delete("/scim/Groups/c617d586-54e6-411d-8e38-649677980001")
      .then()
          .statusCode(HttpStatus.FORBIDDEN.value());
      
      RestAssured.given()
          .header("Authorization", "Bearer " + refreshedToken)
      .when()
          .get("/iam/group/c617d586-54e6-411d-8e38-649677980001/attributes")
      .then()
          .statusCode(HttpStatus.FORBIDDEN.value());
      
      RestAssured.given()
          .header("Authorization", "Bearer " + refreshedToken)
      .when()
          .get("/iam/me/authorities")
      .then()
          .statusCode(HttpStatus.FORBIDDEN.value());

      RestAssured.given()
          .header("Authorization", "Bearer " + refreshedToken)
      .when()
          .get("/iam/api/clients")
      .then()
          .statusCode(HttpStatus.FORBIDDEN.value());
      
      RestAssured.given()
          .header("Authorization", "Bearer " + refreshedToken)
      .when()
          .get("/iam/scope_policies")
      .then()
          .statusCode(HttpStatus.FORBIDDEN.value());
      
      ValidatableResponse resp7= RestAssured.given()
        .formParam("grant_type", "refresh_token")
        .formParam("refresh_token", refreshToken)
        .formParam("scope", "openid scim:read scim:write")
        .auth()
        .preemptive()
          .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
        .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());
      // @formatter:on

    refreshedToken =
        mapper.readTree(resp7.extract().body().asString()).get("access_token").asText();

 // @formatter:off
    RestAssured.given()
        .header("Authorization", "Bearer " + refreshedToken)
    .when()
      .get("/scim/Users")
    .then()
      .statusCode(HttpStatus.OK.value());
    
    RestAssured.given()
        .header("Authorization", "Bearer " + refreshedToken)
    .when()
        .get("/scim/Groups")
    .then()
        .statusCode(HttpStatus.OK.value());
    
    RestAssured.given()
        .header("Authorization", "Bearer " + refreshedToken)
    .when()
        .get("/scim/Users/80e5fb8d-b7c8-451a-89ba-346ae278a66f")
    .then()
        .statusCode(HttpStatus.OK.value());
    
    RestAssured.given()
        .header("Authorization", "Bearer " + refreshedToken)
    .when()
        .get("/scim/Groups/c617d586-54e6-411d-8e38-649677980001")
    .then()
        .statusCode(HttpStatus.OK.value());

    ValidatableResponse resp8= RestAssured.given()
        .formParam("grant_type", "refresh_token")
        .formParam("refresh_token", refreshToken)
        .formParam("scope", "openid iam:admin.read iam:admin.write")
        .auth()
        .preemptive()
          .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
        .post(tokenUrl)
      .then()
      .statusCode(HttpStatus.OK.value());
      // @formatter:on

    refreshedToken =
        mapper.readTree(resp8.extract().body().asString()).get("access_token").asText();
    
// @formatter:off
    RestAssured.given()
        .header("Authorization", "Bearer " + refreshedToken)
    .when()
        .get("/iam/group/c617d586-54e6-411d-8e38-649677980001/attributes")
    .then()
        .statusCode(HttpStatus.OK.value());

    RestAssured.given()
        .header("Authorization", "Bearer " + refreshedToken)
    .when()
        .get("/iam/me/authorities")
    .then()
        .statusCode(HttpStatus.OK.value());

    RestAssured.given()
        .header("Authorization", "Bearer " + refreshedToken)
    .when()
        .get("/iam/api/clients")
    .then()
        .statusCode(HttpStatus.OK.value());

    RestAssured.given()
        .header("Authorization", "Bearer " + refreshedToken)
    .when()
        .get("/iam/scope_policies")
    .then()
        .statusCode(HttpStatus.OK.value());    
        // @formatter:on


  }

}
