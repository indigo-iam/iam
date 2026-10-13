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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

import java.time.Instant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import dev.samstevens.totp.code.DefaultCodeGenerator;
import io.restassured.RestAssured;
import io.restassured.http.Cookie;
import io.restassured.response.Response;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Algorithm;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

/**
 * End to end exercise of the mandatory passkey policy against a running IAM: a user who only owns
 * an authenticator app can use it one last time, is then forced to register a passkey before
 * anything else, and from that moment on only the passkey is accepted as second factor
 */
@ExtendWith(SpringExtension.class)
@IamRandomPortIntegrationTest
// The test data TOTP secret is encrypted with the key of IamTotpMfaCommons.KEY_TO_ENCRYPT_DECRYPT
@TestPropertySource(properties = {"mfa.passkey.enabled=true", "mfa.passkey.mandatory=true",
    "mfa.password-to-encrypt-and-decrypt=define_me_please"})
public class PasskeyMandatoryAuthenticationTests extends PasskeyAuthenticationTestSupport {

  public static final String TOTP_USERNAME = "test-with-mfa";
  public static final String TOTP_PASSWORD = "password";
  public static final long TOTP_ACCOUNT_ID = 1000L;
  private static final long TOTP_PERIOD_SECONDS = 30L;

  @Autowired
  IamTotpMfaRepository totpMfaRepository;

  @Autowired
  IamTotpMfaProperties totpMfaProperties;

  @AfterEach
  void cleanup() {
    cleanupPasskeysAndNotifications(TOTP_USERNAME);
  }

  private String currentTotp() throws Exception {
    IamTotpMfa totpMfa = totpMfaRepository.findByAccountId(TOTP_ACCOUNT_ID).orElseThrow();
    String secret = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecret(totpMfa.getSecret(),
        totpMfaProperties.getPasswordToEncryptAndDecrypt());
    return new DefaultCodeGenerator().generate(secret,
        Math.floorDiv(Instant.now().getEpochSecond(), TOTP_PERIOD_SECONDS));
  }

  @Test
  void authenticatorAppUserMustRegisterAPasskeyAndThenUseIt() throws Exception {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);

    // The authenticator app still gets the user through the second factor...
    Cookie session = startAuthorization();
    Response loginResponse = login(session, TOTP_USERNAME, TOTP_PASSWORD);
    assertThat(loginResponse.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(loginResponse.getHeader("Location"), is(verifyUrl));
    session = sessionAfter(loginResponse, session);

    String page = verifyPage(session);
    assertThat(page, containsString("id=\"totp\""));
    assertThat(page, not(containsString("passkey-verify-form")));

    Response verified = verifyWithTotp(session, csrfTokenFrom(page), currentTotp());
    assertThat(verified.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(verified.getHeader("Location"), containsString("/authorize"));
    session = sessionAfter(verified, session);

    // ...but nothing else is reachable until a passkey is registered
    Response blocked = authorize(session);
    assertThat(blocked.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(blocked.getHeader("Location"), is(activateUrl));

    // @formatter:off
    RestAssured.given()
        .cookie(session)
      .when()
        .get(activateUrl)
      .then()
        .statusCode(HttpStatus.OK.value())
        .body(containsString("activateMfa"));
    // @formatter:on

    registerPasskey(session, authenticator);
    assertThat(passkeyRepository.findByAccountUsername(TOTP_USERNAME), hasSize(1));

    // The enrolment page is no longer imposed
    assertThat(authorize(session).getHeader("Location"), not(is(activateUrl)));

    logout(session);

    // From now on only the passkey is accepted as second factor
    session = startAuthorization();
    loginResponse = login(session, TOTP_USERNAME, TOTP_PASSWORD);
    assertThat(loginResponse.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(loginResponse.getHeader("Location"), is(verifyUrl));
    session = sessionAfter(loginResponse, session);

    page = verifyPage(session);
    assertThat(page, containsString("passkey-verify-form"));
    assertThat(page, not(containsString("id=\"totp\"")));
    String csrf = csrfTokenFrom(page);

    Response rejected = verifyWithTotp(session, csrf, currentTotp());
    assertThat(rejected.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(rejected.getHeader("Location"), containsString("/iam/verify?error=failure"));

    Response accepted = verifyWithPasskey(session, csrf, assertion(session, authenticator, 1));
    assertThat(accepted.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(accepted.getHeader("Location"), containsString("/authorize"));
    session = sessionAfter(accepted, session);
    assertThat(authorize(session).getHeader("Location"), not(is(activateUrl)));
  }
}
