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

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.restassured.RestAssured;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@IamRandomPortIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.RANDOM_PORT)
@Transactional
class IamClientApprovalTests {

  static final String TEST_CLIENT_ID = "client";
  static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  static final String LOCALHOST_URL_TEMPLATE = "http://localhost:%d";

  static final String RESPONSE_TYPE_CODE = "code";

  static final String SCOPE = "openid profile email address phone offline_access";

  static final String TEST_USER_ID = "test";
  static final String TEST_USER_PASSWORD = "password";

  @Value("${local.server.port}")
  Integer iamPort;

  @Autowired
  ObjectMapper mapper;

  String loginUrl;
  String authorizeUrl;

  @BeforeAll
  static void init() {
    TestUtils.initRestAssured();
  }

  @BeforeEach
  void setup() {
    RestAssured.port = iamPort;
    loginUrl = String.format(LOCALHOST_URL_TEMPLATE + "/login", iamPort);
    authorizeUrl = String.format(LOCALHOST_URL_TEMPLATE + "/authorize", iamPort);
  }

  @Test
  void testApprove() {

    CookieFilter cookies = new CookieFilter();

    // Obtain the CSRF cookie before submitting credentials.
    ValidatableResponse loginPage = RestAssured.given()
      .filter(cookies)
      .redirects()
      .follow(false)
      .when()
      .get(loginUrl)
      .then()
      .statusCode(HttpStatus.OK.value());

    String csrfToken = loginPage.extract().cookie("XSRF-TOKEN");
    assertNotNull(csrfToken, "Expected a CSRF cookie from GET /login");

    RestAssured.given()
      .filter(cookies)
      .header("X-XSRF-TOKEN", csrfToken)
      .formParam("username", TEST_USER_ID)
      .formParam("password", TEST_USER_PASSWORD)
      .formParam("submit", "Login")
      .redirects()
      .follow(false)
      .when()
      .post(loginUrl)
      .then()
      .log()
      .ifValidationFails()
      .statusCode(HttpStatus.FOUND.value());

    RestAssured.given()
      .filter(cookies)
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
      .ifValidationFails()
      .statusCode(HttpStatus.OK.value())
      .body(containsString("IAM client consent page"));
  }
}
