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

import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.ADD_SECRET_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.ENABLE_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_ACTIVATE_URL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.jayway.jsonpath.JsonPath;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.TokenGetterUtils;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
@TestPropertySource(properties = {"mfa.multi-factor-mandatory=true",
    "mfa.password-to-encrypt-and-decrypt=test-password"})
class FirstTimeMfaEnrollmentIntegrationTests extends TokenGetterUtils {

  public static final String LOGIN_URL = "http://localhost/login";
  public static final String AUTHORIZE_URL = "http://localhost/authorize";
  public static final String SCOPE = "openid profile";

  private String generateCurrentTotp(String secret) throws Exception {
    CodeGenerator codeGenerator = new DefaultCodeGenerator();
    TimeProvider timeProvider = new SystemTimeProvider();
    long counter = Math.floorDiv(timeProvider.getTime(), 30);
    return codeGenerator.generate(secret, counter);
  }

  @Test
  void firstTimeMfaEnrollmentResumesOriginalAuthorizeRequestAndRotatesSessionId() throws Exception {

    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", "code")
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build();

    String authzEndpointUrl = uriComponents.toUriString();

    // 1. Start the authorization request.
    MvcResult authorizeResult = mvc.perform(get(authzEndpointUrl))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(LOGIN_URL))
      .andReturn();

    MockHttpSession session = (MockHttpSession) authorizeResult.getRequest().getSession();

    // 2. Complete username/password authentication.
    // The user is authenticated only with PRE_AUTHENTICATED because MFA is mandatory.
    MvcResult loginResult = mvc
      .perform(post(LOGIN_URL).session(session)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(MFA_ACTIVATE_URL))
      .andReturn();

    session = (MockHttpSession) loginResult.getRequest().getSession();

    SecurityContext context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");

    assertNotNull(context);
    assertNotNull(context.getAuthentication());

    // 3. Generate the TOTP secret.
    MvcResult addSecretResult =
        mvc.perform(put(ADD_SECRET_URL).session(session).with(securityContext(context)))
          .andExpect(status().isOk())
          .andReturn();

    String secret = JsonPath.read(addSecretResult.getResponse().getContentAsString(), "$.secret");

    String totp = generateCurrentTotp(secret);

    // Capture the session ID immediately before the MFA upgrade.
    String preMfaSessionId = session.getId();

    // 4. Complete MFA enrollment.
    // The session ID must be rotated, while the original saved /authorize request must still be
    // available.
    MvcResult enableResult = mvc
      .perform(post(ENABLE_URL).session(session).with(securityContext(context)).param("code", totp))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.redirectUrl").value(uriComponents.encode().toUriString()))
      .andReturn();

    MockHttpSession upgradedSession = (MockHttpSession) enableResult.getRequest().getSession();

    // Verify session fixation protection.
    assertNotEquals(preMfaSessionId, upgradedSession.getId());

    // Verify that the authentication has been upgraded.
    SecurityContext upgradedContext =
        (SecurityContext) upgradedSession.getAttribute("SPRING_SECURITY_CONTEXT");

    assertNotNull(upgradedContext);
    assertNotNull(upgradedContext.getAuthentication());
    assertTrue(upgradedContext.getAuthentication().isAuthenticated());

    // The original authorization request must be resumed.
    assertEquals(uriComponents.encode().toUriString(),
        JsonPath.read(enableResult.getResponse().getContentAsString(), "$.redirectUrl"));
  }

  @Test
  void invalidTotpDoesNotRotateSessionIdOrUpgradeAuthentication() throws Exception {

    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", "code")
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build();

    String authzEndpointUrl = uriComponents.toUriString();

    MvcResult authorizeResult = mvc.perform(get(authzEndpointUrl))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(LOGIN_URL))
      .andReturn();

    MockHttpSession session = (MockHttpSession) authorizeResult.getRequest().getSession();

    MvcResult loginResult = mvc
      .perform(post(LOGIN_URL).session(session)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(MFA_ACTIVATE_URL))
      .andReturn();

    session = (MockHttpSession) loginResult.getRequest().getSession();

    SecurityContext context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");

    assertNotNull(context);
    assertNotNull(context.getAuthentication());

    MvcResult addSecretResult =
        mvc.perform(put(ADD_SECRET_URL).session(session).with(securityContext(context)))
          .andExpect(status().isOk())
          .andReturn();

    String secret = JsonPath.read(addSecretResult.getResponse().getContentAsString(), "$.secret");

    // Make sure the secret is actually valid, but deliberately use an invalid TOTP code for the MFA
    // verification.
    String validTotp = generateCurrentTotp(secret);
    String invalidTotp = validTotp.equals("000000") ? "000001" : "000000";

    String preMfaSessionId = session.getId();

    MvcResult enableResult = mvc.perform(
        post(ENABLE_URL).session(session).with(securityContext(context)).param("code", invalidTotp))
      .andReturn();

    MockHttpSession afterFailedMfaSession =
        (MockHttpSession) enableResult.getRequest().getSession();

    assertEquals(preMfaSessionId, afterFailedMfaSession.getId());

    // The authentication must not be upgraded to fully authenticated.
    SecurityContext afterFailedMfaContext =
        (SecurityContext) afterFailedMfaSession.getAttribute("SPRING_SECURITY_CONTEXT");

    assertNotNull(afterFailedMfaContext);
    assertNotNull(afterFailedMfaContext.getAuthentication());
    assertFalse(afterFailedMfaContext.getAuthentication().isAuthenticated());

    assertTrue(afterFailedMfaContext.getAuthentication()
      .getAuthorities()
      .stream()
      .anyMatch(authority -> "ROLE_PRE_AUTHENTICATED".equals(authority.getAuthority())));

    assertFalse(afterFailedMfaContext.getAuthentication()
      .getAuthorities()
      .stream()
      .anyMatch(authority -> "ROLE_USER".equals(authority.getAuthority())));
  }
}
