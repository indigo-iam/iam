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
package it.infn.mw.iam.test.multi_factor_authentication.passkey;

import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.AUTHENTICATION_OPTIONS_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.BASE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REGISTRATION_OPTIONS_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REGISTRATION_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REMOVAL_OPTIONS_URL;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.http.Cookie;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionOptionsDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRegistrationDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRegistrationOptionsDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRemovalDTO;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;
import it.infn.mw.iam.test.TestUtils;

/**
 * Shared plumbing for the end to end passkey tests, which run against a random port IAM with
 * RestAssured: authorization code flow start, form login, logout, the /iam/verify page and the
 * passkey ceremonies driven through the REST API.
 *
 * The WebAuthn origin is the one derived from iam.baseUrl (http://localhost:8080), which is what
 * a browser would put in the client data; it does not need to match the random test port
 */
public abstract class PasskeyAuthenticationTestSupport extends PasskeyTestSupport {

  public static final String TEST_CLIENT_ID = "client";
  public static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";
  public static final String LOCALHOST_URL_TEMPLATE = "http://localhost:%d";
  public static final String SCOPE = "openid profile";

  private static final Pattern CSRF_PATTERN =
      Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

  @Autowired
  protected IamPasskeyRepository passkeyRepository;

  @Autowired
  protected IamEmailNotificationRepository notificationRepository;

  @Value("${local.server.port}")
  private Integer iamPort;

  protected final ObjectMapper mapper = new ObjectMapper();

  protected String loginUrl;
  protected String authorizeUrl;
  protected String verifyUrl;
  protected String activateUrl;
  protected String logoutUrl;

  @BeforeAll
  static void init() {
    TestUtils.initRestAssured();
  }

  @BeforeEach
  void setupUrls() {
    RestAssured.port = iamPort;
    loginUrl = String.format(LOCALHOST_URL_TEMPLATE + "/login", iamPort);
    authorizeUrl = String.format(LOCALHOST_URL_TEMPLATE + "/authorize", iamPort);
    verifyUrl = String.format(LOCALHOST_URL_TEMPLATE + "/iam/verify", iamPort);
    activateUrl = String.format(LOCALHOST_URL_TEMPLATE + "/iam/mfa/activate", iamPort);
    logoutUrl = String.format(LOCALHOST_URL_TEMPLATE + "/logout", iamPort);
  }

  /**
   * The ceremonies run against the real server, outside any test transaction: the passkeys and
   * the e-mails they queue must not leak into other tests
   */
  protected void cleanupPasskeysAndNotifications(String username) {
    passkeyRepository.deleteAll(passkeyRepository.findByAccountUsername(username));
    notificationRepository
      .deleteAll(notificationRepository.findByNotificationType(IamNotificationType.MFA_ENABLE));
    notificationRepository
      .deleteAll(notificationRepository.findByNotificationType(IamNotificationType.MFA_DISABLE));
  }

  protected RequestSpecification authorizationRequest(Cookie session) {
    RequestSpecification request = RestAssured.given()
      .queryParam("response_type", "code")
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1");
    if (session != null) {
      request = request.cookie(session);
    }
    return request.redirects().follow(false);
  }

  protected Cookie startAuthorization() {
    // @formatter:off
    return authorizationRequest(null)
      .when()
        .get(authorizeUrl)
      .then()
        .statusCode(HttpStatus.FOUND.value())
        .header("Location", is(loginUrl))
        .extract().detailedCookie("JSESSIONID");
    // @formatter:on
  }

  protected Response authorize(Cookie session) {
    return authorizationRequest(session).when().get(authorizeUrl);
  }

  protected Response login(Cookie session, String username, String password) {
    // @formatter:off
    return RestAssured.given()
        .formParam("username", username)
        .formParam("password", password)
        .formParam("submit", "Login")
        .cookie(session)
        .redirects().follow(false)
      .when()
        .post(loginUrl);
    // @formatter:on
  }

  protected Cookie sessionAfter(Response response, Cookie previous) {
    Cookie renewed = response.getDetailedCookie("JSESSIONID");
    return renewed != null ? renewed : previous;
  }

  protected void logout(Cookie session) {
    RestAssured.given().cookie(session).redirects().follow(false).when().post(logoutUrl);
  }

  protected void registerPasskey(Cookie session, PasskeyTestAuthenticator authenticator)
      throws Exception {
    registerPasskey(session, authenticator, false);
  }

  protected void registerPasskey(Cookie session, PasskeyTestAuthenticator authenticator,
      boolean userVerified) throws Exception {
    // @formatter:off
    registrationResponse(session, authenticator, userVerified, TEST_LABEL)
      .then()
        .statusCode(HttpStatus.CREATED.value())
        .body("label", is(TEST_LABEL));
    // @formatter:on
  }

  protected PasskeyRegistrationOptionsDTO registrationOptions(Cookie session) throws Exception {
    // @formatter:off
    String optionsJson = RestAssured.given()
        .cookie(session)
      .when()
        .post(REGISTRATION_OPTIONS_URL)
      .then()
        .statusCode(HttpStatus.OK.value())
        .extract().asString();
    // @formatter:on
    PasskeyRegistrationOptionsDTO options =
        mapper.readValue(optionsJson, PasskeyRegistrationOptionsDTO.class);
    assertThat(options.getRp().getId(), is(TEST_RP_ID));
    return options;
  }

  /**
   * Runs the whole registration ceremony and returns the raw response of the registration
   * endpoint, so that callers can assert on a rejected registration as well
   */
  protected Response registrationResponse(Cookie session, PasskeyTestAuthenticator authenticator,
      boolean userVerified, String label) throws Exception {
    PasskeyRegistrationOptionsDTO options = registrationOptions(session);
    PasskeyRegistrationDTO registration = registrationFor(authenticator, options.getChallenge(),
        TEST_ORIGIN, userVerified, List.of("usb"), label);

    // @formatter:off
    return RestAssured.given()
        .cookie(session)
        .contentType(ContentType.JSON)
        .body(mapper.writeValueAsString(registration))
      .when()
        .post(REGISTRATION_URL);
    // @formatter:on
  }

  /**
   * Password login of a user who is asked for a second factor: returns the pre-authenticated
   * session, parked at the verification page
   */
  protected Cookie loginExpectingVerification(String username, String password) {
    Cookie session = startAuthorization();
    Response loginResponse = login(session, username, password);
    assertThat(loginResponse.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(loginResponse.getHeader("Location"), is(verifyUrl));
    return sessionAfter(loginResponse, session);
  }

  /**
   * Password login of a user without any factor: returns the fully authenticated session
   */
  protected Cookie loginWithoutSecondFactor(String username, String password) {
    Cookie session = startAuthorization();
    Response loginResponse = login(session, username, password);
    assertThat(loginResponse.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(loginResponse.getHeader("Location"), containsString("/authorize"));
    return sessionAfter(loginResponse, session);
  }

  protected void assertVerificationFailed(Response response) {
    assertThat(response.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(response.getHeader("Location"), containsString("/iam/verify?error=failure"));
  }

  protected Cookie assertVerificationSucceeded(Response response, Cookie previous) {
    assertThat(response.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(response.getHeader("Location"), containsString("/authorize"));
    return sessionAfter(response, previous);
  }

  protected String verifyPage(Cookie session) {
    // @formatter:off
    return RestAssured.given()
        .cookie(session)
      .when()
        .get(verifyUrl)
      .then()
        .statusCode(HttpStatus.OK.value())
        .extract().asString();
    // @formatter:on
  }

  /**
   * CSRF protection is disabled on the main security chain, so the token is only sent when the
   * page actually renders one
   */
  protected String csrfTokenFrom(String page) {
    Matcher matcher = CSRF_PATTERN.matcher(page);
    return matcher.find() ? matcher.group(1) : null;
  }

  protected PasskeyAssertionDTO assertion(Cookie session, PasskeyTestAuthenticator authenticator,
      long signCount) throws Exception {
    PasskeyAssertionOptionsDTO options = assertionOptions(session);
    assertThat(options.getAllowCredentials(), hasSize(1));
    return assertionFor(authenticator, options.getChallenge(), TEST_ORIGIN, false, signCount, null);
  }

  /**
   * Like {@link #assertion(Cookie, PasskeyTestAuthenticator, long)} but without any expectation
   * on the number of registered credentials, and with the user verification flag chosen by the
   * caller
   */
  protected PasskeyAssertionDTO assertion(Cookie session, PasskeyTestAuthenticator authenticator,
      long signCount, boolean userVerified) throws Exception {
    PasskeyAssertionOptionsDTO options = assertionOptions(session);
    return assertionFor(authenticator, options.getChallenge(), TEST_ORIGIN, userVerified,
        signCount, null);
  }

  protected PasskeyAssertionOptionsDTO assertionOptions(Cookie session) throws Exception {
    // @formatter:off
    String optionsJson = RestAssured.given()
        .cookie(session)
      .when()
        .post(AUTHENTICATION_OPTIONS_URL)
      .then()
        .statusCode(HttpStatus.OK.value())
        .extract().asString();
    // @formatter:on
    return mapper.readValue(optionsJson, PasskeyAssertionOptionsDTO.class);
  }

  protected Response verifyWithPasskey(Cookie session, String csrf, PasskeyAssertionDTO assertion)
      throws Exception {
    return verify(session, csrf, "passkey", mapper.writeValueAsString(assertion));
  }

  /**
   * The proof of possession that accompanies a removal: an assertion of the given authenticator
   * against a freshly issued removal challenge
   */
  protected PasskeyRemovalDTO removalProof(Cookie session, PasskeyTestAuthenticator authenticator,
      long signCount) throws Exception {
    // @formatter:off
    String optionsJson = RestAssured.given()
        .cookie(session)
      .when()
        .post(REMOVAL_OPTIONS_URL)
      .then()
        .statusCode(HttpStatus.OK.value())
        .extract().asString();
    // @formatter:on
    PasskeyAssertionOptionsDTO options =
        mapper.readValue(optionsJson, PasskeyAssertionOptionsDTO.class);
    PasskeyRemovalDTO proof = new PasskeyRemovalDTO();
    proof.setAssertion(
        assertionFor(authenticator, options.getChallenge(), TEST_ORIGIN, false, signCount, null));
    return proof;
  }

  protected PasskeyRemovalDTO totpProof(String totp) {
    PasskeyRemovalDTO proof = new PasskeyRemovalDTO();
    proof.setTotp(totp);
    return proof;
  }

  /**
   * Removes a passkey; a null proof sends no body at all
   */
  protected Response removePasskey(Cookie session, String uuid, PasskeyRemovalDTO proof)
      throws Exception {
    RequestSpecification request = RestAssured.given().cookie(session);
    if (proof != null) {
      request = request.contentType(ContentType.JSON).body(mapper.writeValueAsString(proof));
    }
    return request.when().delete(BASE_URL + "/" + uuid);
  }

  protected Response verifyWithTotp(Cookie session, String csrf, String totp) {
    return verify(session, csrf, "totp", totp);
  }

  private Response verify(Cookie session, String csrf, String parameter, String value) {
    // @formatter:off
    RequestSpecification request = RestAssured.given()
        .cookie(session)
        .formParam(parameter, value);
    if (csrf != null) {
      request = request.formParam("_csrf", csrf);
    }
    return request
        .redirects().follow(false)
      .when()
        .post(verifyUrl);
    // @formatter:on
  }

  protected String extractChallenge(PasskeyAssertionDTO assertion) throws Exception {
    byte[] clientData = java.util.Base64.getUrlDecoder()
      .decode(assertion.getResponse().getClientDataJSON());
    return mapper.readTree(clientData).get("challenge").asText();
  }
}
