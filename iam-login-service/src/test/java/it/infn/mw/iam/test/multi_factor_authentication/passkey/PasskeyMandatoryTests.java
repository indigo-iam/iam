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

import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.REQUESTING_MFA;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.BASE_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_ACTIVATE_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.time.Clock;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DefaultIamPasskeyService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

/**
 * With mfa.passkey.mandatory=true every account must own a passkey: users without one are sent to
 * the enrolment page (an authenticator app alone is not enough), the verification page offers
 * only the passkey once there is one, and the last passkey cannot be removed
 */
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"mfa.passkey.enabled=true", "mfa.passkey.mandatory=true"})
class PasskeyMandatoryTests extends PasskeyTestSupport {

  private static final String TEST_USER = "test";
  private static final String TOTP_USER = "test-with-mfa";
  private static final String DASHBOARD_URL = "/dashboard";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamPasskeyRepository passkeyRepository;

  @Autowired
  private IamAccountRepository accountRepository;

  @Autowired
  private Clock clock;

  private IamPasskey storePasskeyFor(String username) {
    IamAccount account = accountRepository.findByUsername(username).orElseThrow();
    return passkeyRepository.save(placeholderPasskey(account, clock.instant()));
  }

  @Test
  @WithMockUser(username = TOTP_USER, roles = {"USER"})
  void userWithOnlyAnAuthenticatorAppIsSentToPasskeyEnrolment() throws Exception {
    mvc.perform(get(DASHBOARD_URL))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(MFA_ACTIVATE_URL));

    mvc.perform(get(MFA_ACTIVATE_URL))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/activateMfa"));
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void userWithoutAnyFactorIsSentToPasskeyEnrolment() throws Exception {
    mvc.perform(get(DASHBOARD_URL))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(MFA_ACTIVATE_URL));
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void userWithAPasskeyIsNotRedirectedAndCannotReachTheEnrolmentPage() throws Exception {
    storePasskeyFor(TEST_USER);

    mvc.perform(get(DASHBOARD_URL)).andExpect(status().isOk());
    mvc.perform(get(MFA_ACTIVATE_URL)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = TOTP_USER, roles = {"PRE_AUTHENTICATED"})
  void authenticatorAppIsStillOfferedUntilAPasskeyIsRegistered() throws Exception {
    mvc.perform(get(MFA_VERIFY_URL))
      .andExpect(status().isOk())
      .andExpect(model().attribute("isAuthenticatorAppActive", true))
      .andExpect(model().attribute("isPasskeyActive", false));
  }

  /**
   * External logins (OIDC, SAML, X.509) hold a pre-authenticated token that the enforcement
   * filter cannot tell apart from a full authentication: the verification page must stay
   * reachable, or a user who still owns only an authenticator app could never verify it
   */
  @Test
  @WithMockUser(username = TOTP_USER, roles = {"PRE_AUTHENTICATED"})
  void verificationPageStaysReachableWithASessionWhilePasskeyEnrolmentIsPending()
      throws Exception {
    mvc.perform(get(MFA_VERIFY_URL).session(new MockHttpSession()))
      .andExpect(status().isOk())
      .andExpect(model().attribute("isAuthenticatorAppActive", true));
  }

  @Test
  @WithMockUser(username = TOTP_USER, roles = {"USER"})
  void enrolmentPageAssetsAreNotRedirectedDuringForcedEnrolment() throws Exception {
    MockHttpSession session = new MockHttpSession();
    session.setAttribute(REQUESTING_MFA, Boolean.TRUE);

    mvc.perform(get(DASHBOARD_URL).session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(MFA_ACTIVATE_URL));

    mvc.perform(get("/resources/iam/js/passkey/webauthn.js").session(session))
      .andExpect(result -> assertThat(result.getResponse().getStatus(), not(is(302))));
  }

  /**
   * An external login that still owns only an authenticator app may land on the enrolment page
   * before verifying it (bookmark, back button): it is sent to verify first, since a
   * pre-authenticated user cannot enrol while a factor is active
   */
  @Test
  @WithMockUser(username = TOTP_USER, roles = {"PRE_AUTHENTICATED"})
  void preAuthenticatedUserWithAFactorIsSentToVerifyBeforeEnrolling() throws Exception {
    mvc.perform(get(MFA_ACTIVATE_URL).session(new MockHttpSession()))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(MFA_VERIFY_URL));
  }

  @Test
  @WithMockUser(username = TOTP_USER, roles = {"PRE_AUTHENTICATED"})
  void onlyThePasskeyIsOfferedOnceRegistered() throws Exception {
    storePasskeyFor(TOTP_USER);

    mvc.perform(get(MFA_VERIFY_URL))
      .andExpect(status().isOk())
      .andExpect(model().attribute("isAuthenticatorAppActive", false))
      .andExpect(model().attribute("isPasskeyActive", true));
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void lastPasskeyCannotBeRemoved() throws Exception {
    IamPasskey passkey = storePasskeyFor(TEST_USER);

    mvc.perform(delete(BASE_URL + "/" + passkey.getUuid()))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", is(DefaultIamPasskeyService.LAST_PASSKEY_MANDATORY_MESSAGE)));
  }
}
