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

import static it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorSettingsController.MULTI_FACTOR_SETTINGS_FOR_ACCOUNT_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorSettingsController.MULTI_FACTOR_SETTINGS_URL;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class MultiFactorSettingsControllerTests extends MultiFactorTestSupport {

  @Autowired
  MockMvc mvc;

  @MockBean
  IamAccountRepository accountRepository;

  @MockBean
  IamTotpMfaRepository totpMfaRepository;

  Clock clock;
  IamAccount testAccount;
  IamAccount mfaAccount;
  IamTotpMfa totp;

  @BeforeEach
  void setup() {

    clock = Clock.systemUTC();

    mfaAccount = getTotpMfaAccount(clock.instant());
    totp = getTotpMfaFor(mfaAccount, clock.instant());
    Mockito.when(accountRepository.findByUuid(mfaAccount.getUuid())).thenReturn(Optional.of(mfaAccount));
    Mockito.when(accountRepository.findByUsername(mfaAccount.getUsername())).thenReturn(Optional.of(mfaAccount));
    Mockito.when(totpMfaRepository.findByAccount(mfaAccount)).thenReturn(Optional.of(totp));
  }

  @Test
  @WithAnonymousUser
  void testGetMfaAccountSettingNoAuthenticationFails() throws Exception {
    mvc.perform(get(MULTI_FACTOR_SETTINGS_FOR_ACCOUNT_URL, TOTP_UUID))
      .andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void testGetMfaAccountSettingWorksForAdmin() throws Exception {
    mvc.perform(get(MULTI_FACTOR_SETTINGS_FOR_ACCOUNT_URL, TOTP_UUID))
      .andExpect(status().isOk())
      .andExpect((jsonPath("$.authenticatorAppActive", equalTo(true))));
  }

  @Test
  @WithMockUser(username = "group-manager", roles = "GM:6a384bcd-d4b3-4b7f-a2fe-7d897ada0dd1")
  void testGetMfaAccountSettingWorksForGroupManager() throws Exception {
    mvc.perform(get(MULTI_FACTOR_SETTINGS_FOR_ACCOUNT_URL, TOTP_UUID))
      .andExpect(status().isOk())
      .andExpect((jsonPath("$.authenticatorAppActive", equalTo(true))));
  }

  @Test
  @WithMockUser(username = "reader", roles = "READER")
  void testGetMfaAccountSettingWorksForReader() throws Exception {
    mvc.perform(get(MULTI_FACTOR_SETTINGS_FOR_ACCOUNT_URL, TOTP_UUID))
      .andExpect(status().isOk())
      .andExpect((jsonPath("$.authenticatorAppActive", equalTo(true))));
  }

  @Test
  @WithMockUser(username = "test-mfa-user", roles = "USER")
  void testGetMfaAccountSettingWorksForUser() throws Exception {
    mvc.perform(get(MULTI_FACTOR_SETTINGS_FOR_ACCOUNT_URL, TOTP_UUID))
      .andExpect(status().isOk())
      .andExpect((jsonPath("$.authenticatorAppActive", equalTo(true))));
  }

  @Test
  @WithMockUser(username = "test-mfa-user", roles = "USER")
  void testGetMfaSettingWorksForAuthenticatedUser() throws Exception {
    mvc.perform(get(MULTI_FACTOR_SETTINGS_URL))
      .andExpect(status().isOk())
      .andExpect((jsonPath("$.authenticatorAppActive", equalTo(true))));
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  void testGetMfaAccountSettingOfAnotherUserFails() throws Exception {
    mvc.perform(get(MULTI_FACTOR_SETTINGS_FOR_ACCOUNT_URL, TOTP_UUID))
      .andExpect(status().isForbidden());
  }
}
