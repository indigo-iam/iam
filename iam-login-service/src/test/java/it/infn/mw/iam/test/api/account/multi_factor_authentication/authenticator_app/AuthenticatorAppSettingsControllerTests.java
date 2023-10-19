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
package it.infn.mw.iam.test.api.account.multi_factor_authentication.authenticator_app;

import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.ADD_SECRET_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.ENABLE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.DISABLE_URL;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Optional;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockMfaUser;
import it.infn.mw.iam.test.util.WithMockPreAuthenticatedUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class AuthenticatorAppSettingsControllerTests extends MultiFactorTestSupport {

  private MockMvc mvc;

  @Autowired
  private WebApplicationContext context;

  @MockBean
  private IamAccountRepository accountRepository;

  @MockBean
  private IamTotpMfaService totpMfaService;

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();
  }

  @Before
  public void setup() {
    when(accountRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(TEST_ACCOUNT));
    when(accountRepository.findByUsername(TOTP_USERNAME)).thenReturn(Optional.of(TOTP_MFA_ACCOUNT));

    mvc =
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testAddSecret() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);
    totpMfa.setActive(false);
    totpMfa.setAccount(null);
    totpMfa.setSecret("secret");
    when(totpMfaService.addTotpMfaSecret(account)).thenReturn(totpMfa);

    mvc.perform(put(ADD_SECRET_URL)).andExpect(status().isOk());

    // TODO called twice for some reason?
    verify(accountRepository, times(2)).findByUsername(TEST_USERNAME);
    verify(totpMfaService, times(1)).addTotpMfaSecret(account);
  }

  @Test
  @WithAnonymousUser
  public void testAddSecretNoAuthenticationIsUnauthorized() throws Exception {
    mvc.perform(put(ADD_SECRET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testAddSecretPreAuthenticationIsUnauthorized() throws Exception {
    mvc.perform(put(ADD_SECRET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorApp() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);

    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);
    totpMfa.setActive(true);
    totpMfa.setAccount(TEST_ACCOUNT);
    totpMfa.setSecret("secret");
    String totp = "123456";

    when(totpMfaService.verifyTotp(account, totp)).thenReturn(true);
    when(totpMfaService.enableTotpMfa(account)).thenReturn(totpMfa);

    mvc.perform(post(ENABLE_URL).param("totp", totp)).andExpect(status().isOk());

    verify(accountRepository, times(2)).findByUsername(TEST_USERNAME);
    verify(totpMfaService, times(1)).verifyTotp(account, totp);
    verify(totpMfaService, times(1)).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppIncorrectCode() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = "123456";

    when(totpMfaService.verifyTotp(account, totp)).thenReturn(false);

    mvc.perform(post(ENABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, times(1)).verifyTotp(account, totp);
    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppInvalidCharactersInCode() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = "abcdef";

    mvc.perform(post(ENABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppCodeTooShort() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = "12345";

    mvc.perform(post(ENABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppCodeTooLong() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = "1234567";

    mvc.perform(post(ENABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppNullCode() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = null;

    mvc.perform(post(ENABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppEmptyCode() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = "";

    mvc.perform(post(ENABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithAnonymousUser
  public void testEnableAuthenticatorAppNoAuthenticationIsUnauthorized() throws Exception {
    String totp = "123456";

    mvc.perform(post(ENABLE_URL).param("totp", totp)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testEnableAuthenticatorAppPreAuthenticationIsUnauthorized() throws Exception {
    String totp = "123456";

    mvc.perform(post(ENABLE_URL).param("totp", totp)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorApp() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);
    String totp = "123456";

    when(totpMfaService.verifyTotp(account, totp)).thenReturn(true);
    when(totpMfaService.disableTotpMfa(account)).thenReturn(totpMfa);

    mvc.perform(post(DISABLE_URL).param("totp", totp)).andExpect(status().isOk());

    verify(accountRepository, times(2)).findByUsername(TOTP_USERNAME);
    verify(totpMfaService, times(1)).verifyTotp(account, totp);
    verify(totpMfaService, times(1)).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppIncorrectCode() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = "123456";

    when(totpMfaService.verifyTotp(account, totp)).thenReturn(false);

    mvc.perform(post(DISABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, times(1)).verifyTotp(account, totp);
    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppInvalidCharactersInCode() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = "123456";

    mvc.perform(post(DISABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppCodeTooShort() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = "12345";

    mvc.perform(post(DISABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppCodeTooLong() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = "1234567";

    mvc.perform(post(DISABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppNullCode() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = null;

    mvc.perform(post(DISABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppEmptyCode() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = "";

    mvc.perform(post(DISABLE_URL).param("totp", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithAnonymousUser
  public void testDisableAuthenticatorAppNoAuthenticationIsUnauthorized() throws Exception {
    String totp = "123456";

    mvc.perform(post(DISABLE_URL).param("totp", totp)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testDisableAuthenticatorAppPreAuthenticationIsUnauthorized() throws Exception {
    String totp = "123456";

    mvc.perform(post(DISABLE_URL).param("totp", totp)).andExpect(status().isUnauthorized());
  }
}
