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
import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.ValidatableResponse;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

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

  public static final String SCOPE = "openid profile";

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
        .authentication()
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

}
