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

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_ACTIVATE_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;
import static org.mockito.Mockito.times;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.time.Clock;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class MfaVerifyControllerTests extends MultiFactorTestSupport {

  @Autowired
  private MockMvc mvc;

  @MockBean
  private IamAccountRepository accountRepository;

  @MockBean
  private IamTotpMfaRepository totpMfaRepository;

  Clock clock;
  IamAccount testAccount;
  IamAccount mfaAccount;
  IamTotpMfa totp;

  @BeforeEach
  void setup() {

    clock = Clock.systemUTC();

    testAccount = getTestAccount(clock.instant());
    mfaAccount = getTotpMfaAccount(clock.instant());
    totp = getTotpMfaFor(mfaAccount, clock.instant());
    Mockito.when(totpMfaRepository.findByAccount(mfaAccount)).thenReturn(Optional.of(totp));

    Mockito.when(accountRepository.findByUsername(testAccount.getUsername())).thenReturn(Optional.of(testAccount));
    Mockito.when(accountRepository.findByUsername(mfaAccount.getUsername())).thenReturn(Optional.of(mfaAccount));
  }

  @Test
  @WithMockUser(username = "test-mfa-user", authorities = {"ROLE_PRE_AUTHENTICATED"})
  void testGetVerifyMfaView() throws Exception {

    mvc.perform(get(MFA_VERIFY_URL))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("isAuthenticatorAppActive"));

    Mockito.verify(totpMfaRepository, times(1)).findByAccount(mfaAccount);
  }

  @Test
  @WithMockUser(username = "test-mfa-user", authorities = {"ROLE_PRE_AUTHENTICATED"})
  void testGetVerifyMfaViewThrowsNoSuchAccountError() throws Exception {

    Mockito.when(accountRepository.findByUsername(mfaAccount.getUsername())).thenThrow(new NoSuchAccountError(
        String.format("Account not found for username '%s'", mfaAccount.getUsername())));
    mvc.perform(get(MFA_VERIFY_URL)).andExpect(status().isBadRequest());

    Mockito.verify(totpMfaRepository, times(0)).findByAccount(mfaAccount);
  }

  @Test
  void testGetMfaVerifyViewNoAuthenticationIsUnauthorized() throws Exception {
    mvc.perform(get(MFA_VERIFY_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser
  void testGetMfaVerifyViewWithFullAuthenticationIsForbidden() throws Exception {
    mvc.perform(get(MFA_VERIFY_URL)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = "test-mfa-user", authorities = {"ROLE_USER"})
  void testForPreAuthenticatedAuthenticationTokenAuthenticatedSetToFalse() throws Exception {
    List<GrantedAuthority> currentAuthorities =
        Collections.singletonList(new SimpleGrantedAuthority("ROLE_PRE_AUTHENTICATED"));
    User testUser = new User("test-mfa-user", "SECRET", currentAuthorities);

    PreAuthenticatedAuthenticationToken token =
        new PreAuthenticatedAuthenticationToken(testUser, "test-credentials", currentAuthorities);
    SecurityContextHolder.getContext().setAuthentication(token);

    Mockito.when(totpMfaRepository.findByAccount(mfaAccount)).thenReturn(Optional.of(totp));
    mvc.perform(get(MFA_VERIFY_URL))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("isAuthenticatorAppActive"));

    mvc.perform(get("/dashboard")).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(roles = "PRE_AUTHENTICATED")
  void getActivateMfaViewAuthorizedReturnsView() throws Exception {
    mvc.perform(get(MFA_ACTIVATE_URL))
        .andExpect(status().isOk())
        .andExpect(view().name("iam/activateMfa"));
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void getActivateMfaViewWrongRoleForbidden() throws Exception {
    mvc.perform(get(MFA_ACTIVATE_URL))
        .andExpect(status().isForbidden());
  }

  @Test
  @WithAnonymousUser
  void getActivateMfaViewAnonymousUnauthorized() throws Exception {
    mvc.perform(get(MFA_ACTIVATE_URL))
        .andExpect(status().isUnauthorized());
  }
}
