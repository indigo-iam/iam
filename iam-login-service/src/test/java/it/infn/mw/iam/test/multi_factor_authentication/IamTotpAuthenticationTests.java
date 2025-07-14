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
package it.infn.mw.iam.test.multi_factor_authentication;

import static org.hamcrest.CoreMatchers.is;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
public class IamTotpAuthenticationTests {

  @Autowired
  IamTotpMfaRepository totpMfaRepo;

  @Value("${local.server.port}")
  private Integer iamPort;

  public static final String TEST_CLIENT_ID = "client";
  public static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  public static final String LOCALHOST_URL_TEMPLATE = "http://localhost:%d";

  public static final String RESPONSE_TYPE_CODE = "code";

  public static final String SCOPE =
      "openid profile scim:read scim:write offline_access iam:admin.read iam:admin.write";

  private String loginUrl;
  private String authorizeUrl;
  private String verifyUrl;

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();

  }

  @Before
  public void setup() {
    RestAssured.port = iamPort;
    loginUrl = String.format(LOCALHOST_URL_TEMPLATE + "/login", iamPort);
    authorizeUrl = String.format(LOCALHOST_URL_TEMPLATE + "/authorize", iamPort);
    verifyUrl = String.format(LOCALHOST_URL_TEMPLATE + "/iam/verify", iamPort);
  }

  @Test
  public void testRedirectToVerifyPageAfterLogin() {

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
      RestAssured.given()
        .formParam("username", "test-with-mfa")
        .formParam("password", "password")
        .formParam("submit", "Login")
        .cookie(resp1.extract().detailedCookie("JSESSIONID"))
        .redirects().follow(false)
      .when()
        .post(loginUrl)
      .then()
        .statusCode(HttpStatus.FOUND.value())
        .header("Location", is(verifyUrl));
      // @formatter:on
  }

  @Test
  public void testRedirectToAuthorizeUrlWhenTotpIsInactive() {

    IamTotpMfa totp = totpMfaRepo.findByAccountId(Long.valueOf(1000)).orElseThrow();
    totp.setActive(false);
    totpMfaRepo.save(totp);

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
      RestAssured.given()
        .formParam("username", "test-with-mfa")
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
        .cookie(resp1.extract().detailedCookie("JSESSIONID"))
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

    totp.setActive(true);
    totpMfaRepo.save(totp);
  }
}
