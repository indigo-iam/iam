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

import static org.hamcrest.CoreMatchers.is;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.PKCEAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;

import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@ExtendWith(SpringExtension.class)
@IamRandomPortIntegrationTest
class AuthorizationCodeWithPKCEIntegrationTests extends ScopePolicyTestUtils {

  static final String TEST_CLIENT_ID = "client";
  static final String TEST_CLIENT_SECRET = "secret";
  static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  static final String LOCALHOST_URL_TEMPLATE = "http://localhost:%d";

  static final String SCOPE = "openid profile";

  static final String TEST_USER_NAME = "test";
  static final String TEST_USER_PASSWORD = "password";

  String loginUrl;
  String authorizeUrl;
  String tokenUrl;

  @Value("${local.server.port}")
  Integer iamPort;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  IamAccountRepository accountRepo;

  IamAccount findTestAccount() {
    return accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found!"));
  }

  private static String generateCodeVerifier() {
    SecureRandom sr = new SecureRandom();
    byte[] code = new byte[32];
    sr.nextBytes(code);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(code);
  }

  private static String generateSha256CodeChallenge(String verifier) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] digest = md.digest(verifier.getBytes(StandardCharsets.US_ASCII));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
  }

  private ValidatableResponse getTokenResponseWithPkce(String codeVerifier, String codeChallenge,
      String codeChallengeMethod) {

    ValidatableResponse resp1 = RestAssured.given()
      .queryParam("response_type", "code")
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .queryParam("code_challenge", codeChallenge)
      .queryParam("code_challenge_method", codeChallengeMethod)
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
      .queryParam("response_type", "code")
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .queryParam("code_challenge", codeChallenge)
      .queryParam("code_challenge_method", codeChallengeMethod)
      .redirects()
      .follow(false)
      .when()
      .get(authorizeUrl)
      .then()
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
      .formParam("code_verifier", codeVerifier)
      .auth()
      .preemptive()
      .basic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)
      .when()
      .post(tokenUrl)
      .then();
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
  void testAuthzCodeWithPkceShaCodeChallenge() throws Exception {

    String codeVerifier = generateCodeVerifier();
    String codeChallenge = generateSha256CodeChallenge(codeVerifier);

    getTokenResponseWithPkce(codeVerifier, codeChallenge, PKCEAlgorithm.S256.getName())
      .statusCode(HttpStatus.OK.value());
  }

  @Test
  void testAuthzCodeWithPkcePlainCodeChallenge() {

    String codeVerifier = generateCodeVerifier();

    getTokenResponseWithPkce(codeVerifier, codeVerifier, PKCEAlgorithm.plain.getName())
      .statusCode(HttpStatus.OK.value());
  }

  @Test
  void testAuthzCodeWithPkceWrongS256Code() throws Exception {

    String codeVerifier = generateCodeVerifier();
    String codeChallenge = generateSha256CodeChallenge(codeVerifier);

    getTokenResponseWithPkce(Base64URL.encode("wrong-verifier").toString(), codeChallenge,
        PKCEAlgorithm.S256.getName()).statusCode(HttpStatus.BAD_REQUEST.value());
  }

  @Test
  void testAuthzCodeWithPkceWrongPlainCode() throws Exception {

    String codeVerifier = generateCodeVerifier();
    String codeChallenge = generateSha256CodeChallenge(codeVerifier);

    getTokenResponseWithPkce("wrong-verifier", codeChallenge, PKCEAlgorithm.plain.getName())
      .statusCode(HttpStatus.BAD_REQUEST.value());
  }

  @Test
  void testAuthzCodeWithPkceNullCode() throws Exception {

    String codeVerifier = generateCodeVerifier();
    String codeChallenge = generateSha256CodeChallenge(codeVerifier);

    getTokenResponseWithPkce(null, codeChallenge, PKCEAlgorithm.S256.getName())
      .statusCode(HttpStatus.BAD_REQUEST.value());
  }

  @Test
  void testAuthzCodeWithPkceWrongCodeChallengeMethod() throws Exception {

    String codeVerifier = generateCodeVerifier();
    String codeChallenge = generateSha256CodeChallenge(codeVerifier);

    getTokenResponseWithPkce(codeVerifier, codeChallenge, PKCEAlgorithm.NONE.getName())
      .statusCode(HttpStatus.BAD_REQUEST.value());
  }
}
