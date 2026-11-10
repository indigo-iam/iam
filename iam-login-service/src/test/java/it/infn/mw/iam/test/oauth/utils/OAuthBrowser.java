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
package it.infn.mw.iam.test.oauth.utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.SEE_OTHER;

import java.util.Map;

import org.springframework.web.util.UriComponentsBuilder;

import io.restassured.RestAssured;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;

public final class OAuthBrowser {

  private final String loginUrl;
  private final String authorizeUrl;
  private final CookieFilter cookies = new CookieFilter();

  public OAuthBrowser(String baseUrl) {
    String normalizedBaseUrl =
        baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

    loginUrl = normalizedBaseUrl + "/login";
    authorizeUrl = normalizedBaseUrl + "/authorize";
  }

  private RequestSpecification request() {
    return RestAssured.given()
      .filter(cookies)
      .redirects().follow(false);
  }

  public ValidatableResponse authorize(Map<String, ?> parameters) {
    return request()
      .queryParams(parameters)
      .when()
        .get(authorizeUrl)
      .then();
  }

  public ValidatableResponse login(String username, String password) {
    ValidatableResponse loginPage = request()
      .when()
        .get(loginUrl)
      .then()
        .statusCode(OK.value());

    return request()
      .formParam("_csrf", csrfFromPage(loginPage))
      .formParam("username", username)
      .formParam("password", password)
      .formParam("submit", "Login")
      .when()
        .post(loginUrl)
      .then();
  }

  public ValidatableResponse submitConsent(
      ValidatableResponse consentPage, boolean approved, String remember) {

    return request()
      .formParam("_csrf", csrfFromPage(consentPage))
      .formParam("consent_transaction_id", consentTransactionIdFromPage(consentPage))
      .formParam("user_oauth_approval", Boolean.toString(approved))
      .formParam(approved ? "authorize" : "deny",
          approved ? "Authorize" : "Deny")
      .formParam("remember", remember)
      .when()
        .post(authorizeUrl)
      .then();
  }

  public String approve(ValidatableResponse consentPage) {
    ValidatableResponse response =
        submitConsent(consentPage, true, "none")
          .statusCode(SEE_OTHER.value());

    String location = response.extract().header("Location");
    assertNotNull(location, "Expected an authorization redirect");

    String code = UriComponentsBuilder.fromHttpUrl(location)
      .build()
      .getQueryParams()
      .getFirst("code");

    assertNotNull(code, "Expected an authorization code in the redirect");
    assertFalse(code.isBlank(), "Authorization code must not be blank");

    return code;
  }

  private static String consentTransactionIdFromPage(ValidatableResponse page) {
    String transactionId = page.extract()
      .htmlPath()
      .getString(
          "**.find { it.name() == 'input' && it.@name == 'consent_transaction_id' }.@value");

    assertNotNull(transactionId, "Expected a consent transaction ID in the page");
    assertFalse(transactionId.isBlank(), "Consent transaction ID must not be blank");

    return transactionId;
  }

  private static String csrfFromPage(ValidatableResponse page) {
    String token = page.extract()
      .htmlPath()
      .getString(
          "**.find { it.name() == 'input' && it.@name == '_csrf' }.@value");

    assertNotNull(token, "Expected a CSRF token in the page");
    assertFalse(token.isBlank(), "CSRF token must not be blank");

    return token;
  }
}
