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

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_ACTIVATE_URL;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
class MfaVerifyControllerTests extends MultiFactorTestSupport {

  private MockMvc mvc;

  @Autowired
  private WebApplicationContext context;

  @MockBean
  private IamAccountRepository accountRepository;

  @MockBean
  private IamTotpMfaRepository totpMfaRepository;

  @BeforeEach
  void setup() {
    when(accountRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(TEST_ACCOUNT));
    when(accountRepository.findByUsername(TOTP_USERNAME)).thenReturn(Optional.of(TOTP_MFA_ACCOUNT));

    mvc =
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
  }

  @Test
  @WithMockUser(username = "test-mfa-user", authorities = {"ROLE_PRE_AUTHENTICATED"})
  void testGetVerifyMfaView() throws Exception {
    mvc.perform(get(MFA_VERIFY_URL))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("isAuthenticatorAppActive"));

    verify(totpMfaRepository, times(1)).findByAccount(TOTP_MFA_ACCOUNT);
  }

  @Test
  @WithMockUser(username = "test-mfa-user", authorities = {"ROLE_PRE_AUTHENTICATED"})
  void testGetVerifyMfaViewWhenTotpAlreadyPresent() throws Exception {
    when(totpMfaRepository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(TOTP_MFA));
    mvc.perform(get(MFA_VERIFY_URL))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("isAuthenticatorAppActive"));

    verify(totpMfaRepository, times(1)).findByAccount(TOTP_MFA_ACCOUNT);
  }

  @Test
  @WithMockUser(username = "test-mfa-user", authorities = {"ROLE_PRE_AUTHENTICATED"})
  void testGetVerifyMfaViewThrowsNoSuchAccountError() throws Exception {
    when(accountRepository.findByUsername(TOTP_USERNAME)).thenThrow(new NoSuchAccountError(
        String.format("Account not found for username '%s'", TOTP_USERNAME)));
    mvc.perform(get(MFA_VERIFY_URL)).andExpect(status().isBadRequest());

    verify(totpMfaRepository, times(0)).findByAccount(TOTP_MFA_ACCOUNT);
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

    when(totpMfaRepository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(TOTP_MFA));
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
