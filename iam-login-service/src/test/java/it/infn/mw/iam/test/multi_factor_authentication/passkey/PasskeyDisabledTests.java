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

import static it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorSettingsController.MULTI_FACTOR_SETTINGS_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.AUTHENTICATION_OPTIONS_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.BASE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REGISTRATION_OPTIONS_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REGISTRATION_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REMOVAL_OPTIONS_URL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DisabledIamPasskeyService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.IamPasskeyService;
import it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

/**
 * With the default configuration passkeys are disabled: the feature must be invisible and the
 * endpoints must refuse ceremonies, while an administrator can still reset passkeys that were
 * stored before the feature was disabled
 */
@IamMockMvcIntegrationTest
class PasskeyDisabledTests {

  private static final String TEST_USER_UUID = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamPasskeyService passkeyService;

  @Autowired
  private IamPasskeyRepository passkeyRepository;

  @Autowired
  private IamAccountRepository accountRepository;

  @Autowired
  private Clock clock;

  @Test
  void disabledServiceIsWired() {
    org.hamcrest.MatcherAssert.assertThat(passkeyService,
        org.hamcrest.Matchers.instanceOf(DisabledIamPasskeyService.class));
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  void ceremoniesAreRefused() throws Exception {
    mvc.perform(post(REGISTRATION_OPTIONS_URL))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", is(DisabledIamPasskeyService.DISABLED_MESSAGE)));
    mvc.perform(post(REGISTRATION_URL).contentType(MediaType.APPLICATION_JSON).content("{}"))
      .andExpect(status().isBadRequest());
    mvc.perform(post(REMOVAL_OPTIONS_URL))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", is(DisabledIamPasskeyService.DISABLED_MESSAGE)));
    mvc.perform(get(BASE_URL)).andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));
    mvc.perform(delete(BASE_URL + "/" + TEST_USER_UUID))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", is(DisabledIamPasskeyService.PASSKEY_NOT_FOUND_MESSAGE)));
    mvc.perform(get(MULTI_FACTOR_SETTINGS_URL))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.passkeyActive", is(false)));
  }

  /**
   * Credentials stored before the feature was switched off are not accepted at login, but their
   * owner can still see them and remove them, without any proof of a second factor
   */
  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  void storedPasskeysAreListedAndRemovableWhileDisabled() throws Exception {
    IamAccount account = accountRepository.findByUuid(TEST_USER_UUID).orElseThrow();
    IamPasskey stored =
        passkeyRepository.save(PasskeyTestSupport.placeholderPasskey(account, clock.instant()));

    mvc.perform(get(BASE_URL))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$", hasSize(1)))
      .andExpect(jsonPath("$[0].uuid", is(stored.getUuid())));
    mvc.perform(get(MULTI_FACTOR_SETTINGS_URL))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.passkeyActive", is(false)));

    mvc.perform(delete(BASE_URL + "/" + stored.getUuid())).andExpect(status().isNoContent());
    assertThat(passkeyRepository.findByAccountId(account.getId()), empty());
  }

  @Test
  @WithMockUser(username = "test", roles = {"PRE_AUTHENTICATED"})
  void verificationPageHidesPasskeys() throws Exception {
    mvc.perform(post(AUTHENTICATION_OPTIONS_URL)).andExpect(status().isBadRequest());
    mvc.perform(get(MfaVerifyController.MFA_VERIFY_URL))
      .andExpect(status().isOk())
      .andExpect(model().attribute("isPasskeyActive", false));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void adminResetRemovesStoredPasskeys() throws Exception {
    IamAccount account = accountRepository.findByUuid(TEST_USER_UUID).orElseThrow();
    passkeyRepository.save(PasskeyTestSupport.placeholderPasskey(account, clock.instant()));

    mvc.perform(delete(BASE_URL + "/reset/" + TEST_USER_UUID)).andExpect(status().isNoContent());
    assertThat(passkeyRepository.findByAccountId(account.getId()), empty());
  }
}
