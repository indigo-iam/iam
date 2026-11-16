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
package it.infn.mw.iam.test.registration;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

import io.restassured.RestAssured;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.response.Response;
import it.infn.mw.iam.test.TestUtils;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class RegistrationApiControllerTests {

  private static final String CSRF_COOKIE = "XSRF-TOKEN";
  private static final String CSRF_HEADER = "X-XSRF-TOKEN";

  @Value("${local.server.port}")
  private Integer iamPort;

  @BeforeAll
  static void init() {
    TestUtils.initRestAssured();
  }

  @Test
  void testTokenIsNotReflectedInErrorPage() {

    Response loginResponse = RestAssured.given()
      .port(iamPort)
      .redirects()
      .follow(false)
      .when()
      .get("/login")
      .then()
      .statusCode(200)
      .extract()
      .response();

    String csrfToken = loginResponse.getCookie(CSRF_COOKIE);

    assertThat(csrfToken).as("Token CSRF restituito dalla pagina di login").isNotBlank();

    String response = RestAssured.given()
      .port(iamPort)
      .cookies(loginResponse.getCookies())
      .header(CSRF_HEADER, csrfToken)
      .contentType("application/x-www-form-urlencoded")
      .formParam("token", "<img src=x onerror=alert(1)>")
      .redirects()
      .follow(false)
      .when()
      .post("/registration/verify")
      .then()
      .statusCode(200)
      .extract()
      .asString();

    assertThat(response).isNotBlank()
      .doesNotContain("<img src=x onerror=alert(1)>")
      .contains("No registration request found");
  }

  @Test
  void testTokenIsEscapedInConfirmPage() {

    String payload = "\"><img src=x onerror=alert(1)>";

    String response = RestAssured.given()
      .port(iamPort)
      .pathParam("token", payload)
      .redirects()
      .follow(false)
      .when()
      .get("/registration/verify/{token}")
      .then()
      .statusCode(200)
      .extract()
      .asString();

    assertThat(response).isNotBlank().doesNotContain("<img src=x onerror=alert(1)>");
  }

  @Test
  void verificationPageContainsCsrfField() {
    Response page = RestAssured.given()
      .port(iamPort)
      .redirects()
      .follow(false)
      .when()
      .get("/registration/verify/example-token")
      .then()
      .statusCode(200)
      .extract()
      .response();

    assertThat(page.asString()).contains("name=\"confirmationForm\"");
    assertThat(csrfFormToken(page)).isNotBlank();
  }

  @Test
  void verificationPostWithoutCsrfIsForbidden() {
    CookieFilter cookies = new CookieFilter();

    RestAssured.given()
      .port(iamPort)
      .filter(cookies)
      .when()
      .get("/registration/verify/example-token")
      .then()
      .statusCode(200);

    RestAssured.given()
      .port(iamPort)
      .filter(cookies)
      .contentType("application/x-www-form-urlencoded")
      .formParam("token", "example-token")
      .redirects()
      .follow(false)
      .when()
      .post("/registration/verify")
      .then()
      .statusCode(403);
  }

  @Test
  void verificationPostAcceptsCsrfFromForm() {
    CookieFilter cookies = new CookieFilter();

    Response page = RestAssured.given()
      .port(iamPort)
      .filter(cookies)
      .redirects()
      .follow(false)
      .when()
      .get("/registration/verify/example-token")
      .then()
      .statusCode(200)
      .extract()
      .response();

    String csrfToken = csrfFormToken(page);

    // An invalid confirmation token yields an application error page (200),
    // proving the POST passed CSRF validation and reached the controller.
    String response = RestAssured.given()
      .port(iamPort)
      .filter(cookies)
      .contentType("application/x-www-form-urlencoded")
      .formParam("token", "example-token")
      .formParam("_csrf", csrfToken)
      .redirects()
      .follow(false)
      .when()
      .post("/registration/verify")
      .then()
      .statusCode(200)
      .extract()
      .asString();

    assertThat(response).contains("Request confirmation failure");
  }

  private String csrfFormToken(Response page) {
    var matcher = Pattern.compile(
        "<input[^>]*name=\"_csrf\"[^>]*value=\"([^\"]+)\"[^>]*>",
        Pattern.CASE_INSENSITIVE).matcher(page.asString());
    assertThat(matcher.find()).as("CSRF hidden input in verification form").isTrue();
    return matcher.group(1);
  }
}
