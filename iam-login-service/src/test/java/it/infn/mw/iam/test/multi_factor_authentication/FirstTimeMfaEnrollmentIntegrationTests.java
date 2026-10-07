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

/**
 * Proves https://github.com/indigo-iam/iam/issues/1372 end to end, through the real filter chain
 * and a real session, rather than by calling {@code AuthenticationSuccessHandlerHelper} directly
 * (see {@code AuthenticationSuccessHandlerHelperEnrollmentRedirectTests} for that): with mandatory
 * MFA on, a user who starts an OAuth2 authorization code flow, has no TOTP secret yet, and
 * enrolls one, lands back on the client's own {@code /authorize} request instead of on IAM's own
 * dashboard or login page.
 */
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
@TestPropertySource(properties = "mfa.multi-factor-mandatory=true")
class FirstTimeMfaEnrollmentIntegrationTests extends TokenGetterUtils {

  public static final String LOGIN_URL = "http://localhost/login";
  public static final String AUTHORIZE_URL = "http://localhost/authorize";
  public static final String SCOPE = "openid profile";

  // Mirrors the defaults of the CodeVerifier bean the server actually checks against
  // (IamTotpMfaConfig#codeVerifier: SHA1, 6 digits, 30s period) so this generates a code the
  // server will genuinely accept, rather than one only this test believes is valid.
  private String generateCurrentTotp(String secret) throws Exception {
    CodeGenerator codeGenerator = new DefaultCodeGenerator();
    TimeProvider timeProvider = new SystemTimeProvider();
    long counter = Math.floorDiv(timeProvider.getTime(), 30);
    return codeGenerator.generate(secret, counter);
  }

  @Test
  void firstTimeMfaEnrollmentResumesOriginalAuthorizeRequest() throws Exception {

    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", "code")
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build();

    String authzEndpointUrl = uriComponents.toUriString();

    // 1. Start the client's own login flow -- Spring Security saves this request.
    MockHttpSession session = (MockHttpSession) mvc.perform(get(authzEndpointUrl))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(LOGIN_URL))
      .andReturn()
      .getRequest()
      .getSession();

    // 2. Log in. Mandatory MFA + no TOTP secret yet -> sent to enroll, not back to the client.
    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).session(session)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(MFA_ACTIVATE_URL))
      .andReturn()
      .getRequest()
      .getSession();

    SecurityContext context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");

    // 3. Enroll: get a secret, then prove it with a real TOTP code for it.
    MvcResult addSecretResult = mvc
      .perform(put(ADD_SECRET_URL).session(session).with(securityContext(context)))
      .andExpect(status().isOk())
      .andReturn();

    String secret =
        JsonPath.read(addSecretResult.getResponse().getContentAsString(), "$.secret");
    String totp = generateCurrentTotp(secret);

    // 4. This is the bug from #1372: the response must send the browser back to the client's
    // own /authorize request, not to IAM's own dashboard or login page.
    mvc.perform(post(ENABLE_URL).session(session).with(securityContext(context))
        .param("code", totp))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.redirectUrl").value(uriComponents.encode().toUriString()));

    // The redirectUrl alone doesn't prove the session itself was upgraded -- check the session's
    // own stored SecurityContext directly, the same way step 2 above read it out.
    SecurityContext upgradedContext =
        (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
    assertTrue(upgradedContext.getAuthentication().isAuthenticated());
  }
}
