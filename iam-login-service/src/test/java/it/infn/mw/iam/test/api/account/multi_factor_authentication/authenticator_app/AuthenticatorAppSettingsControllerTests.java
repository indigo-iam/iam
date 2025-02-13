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
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.DISABLE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.ENABLE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.MFA_SECRET_NOT_FOUND_MESSAGE;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import org.springframework.web.util.NestedServletException;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.user.exception.MfaSecretAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.core.user.exception.TotpMfaAlreadyEnabledException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockMfaUser;
import it.infn.mw.iam.test.util.WithMockPreAuthenticatedUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

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

  @MockBean
  private IamTotpMfaProperties iamTotpMfaProperties;

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();
  }

  @Before
  public void setup() {
    when(accountRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(TEST_ACCOUNT));
    when(accountRepository.findByUsername(TOTP_USERNAME)).thenReturn(Optional.of(TOTP_MFA_ACCOUNT));
    when(iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()).thenReturn(KEY_TO_ENCRYPT_DECRYPT);

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
    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()));
    when(totpMfaService.addTotpMfaSecret(account)).thenReturn(totpMfa);

    mvc.perform(put(ADD_SECRET_URL)).andExpect(status().isOk());

    verify(accountRepository, times(2)).findByUsername(TEST_USERNAME);
    verify(totpMfaService, times(1)).addTotpMfaSecret(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testAddSecretThrowsMfaSecretAlreadyBoundException() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);
    totpMfa.setActive(false);
    totpMfa.setAccount(null);
    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()));
    when(totpMfaService.addTotpMfaSecret(account)).thenThrow(new MfaSecretAlreadyBoundException(
        "A multi-factor secret is already assigned to this account"));

    mvc.perform(put(ADD_SECRET_URL)).andExpect(status().isConflict());

    verify(accountRepository, times(2)).findByUsername(TEST_USERNAME);
    verify(totpMfaService, times(1)).addTotpMfaSecret(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testAddSecret_withEmptyPassword() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);
    totpMfa.setActive(false);
    totpMfa.setAccount(null);
    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()));

    when(totpMfaService.addTotpMfaSecret(account)).thenReturn(totpMfa);
    when(iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()).thenReturn("");

    NestedServletException thrownException = assertThrows(NestedServletException.class, () -> {
      mvc.perform(put(ADD_SECRET_URL));
    });

    assertTrue(
        thrownException.getCause().getMessage().startsWith("Please ensure that you provide"));
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
    totpMfa.setAccount(account);
    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()));
    String totp = "123456";

    when(totpMfaService.verifyTotp(account, totp)).thenReturn(true);
    when(totpMfaService.enableTotpMfa(account)).thenReturn(totpMfa);

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().isOk());

    verify(accountRepository, times(2)).findByUsername(TEST_USERNAME);
    verify(totpMfaService, times(1)).verifyTotp(account, totp);
    verify(totpMfaService, times(1)).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppThrowsTotpMfaAlreadyEnabledException() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = "123456";

    when(totpMfaService.verifyTotp(account, totp)).thenReturn(true);
    when(totpMfaService.enableTotpMfa(account))
      .thenThrow(new TotpMfaAlreadyEnabledException("TOTP MFA is already enabled on this account"));

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().isConflict());

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

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, times(1)).verifyTotp(account, totp);
    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppButTotpVerificationFails() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = "123456";

    when(totpMfaService.verifyTotp(account, totp))
      .thenThrow(new MfaSecretNotFoundException(MFA_SECRET_NOT_FOUND_MESSAGE));

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, times(1)).verifyTotp(account, totp);
    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppInvalidCharactersInCode() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = "abcdef";

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppCodeTooShort() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = "12345";

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppCodeTooLong() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = "1234567";

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppNullCode() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = null;

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testEnableAuthenticatorAppEmptyCode() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    String totp = "";

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).enableTotpMfa(account);
  }

  @Test
  @WithAnonymousUser
  public void testEnableAuthenticatorAppNoAuthenticationIsUnauthorized() throws Exception {
    String totp = "123456";

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testEnableAuthenticatorAppPreAuthenticationIsUnauthorized() throws Exception {
    String totp = "654321";

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorApp() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);
    String totp = "123456";

    when(totpMfaService.verifyTotp(account, totp)).thenReturn(true);
    when(totpMfaService.disableTotpMfa(account)).thenReturn(totpMfa);

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().isOk());

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

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, times(1)).verifyTotp(account, totp);
    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppButTotpVerificationFails() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = "123456";

    when(totpMfaService.verifyTotp(account, totp))
      .thenThrow(new MfaSecretNotFoundException(MFA_SECRET_NOT_FOUND_MESSAGE));

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, times(1)).verifyTotp(account, totp);
    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppInvalidCharactersInCode() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = "123456";

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppCodeTooShort() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = "12345";

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppCodeTooLong() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = "1234567";

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppNullCode() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = null;

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithMockMfaUser
  public void testDisableAuthenticatorAppEmptyCode() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    String totp = "";

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    verify(totpMfaService, never()).disableTotpMfa(account);
  }

  @Test
  @WithAnonymousUser
  public void testDisableAuthenticatorAppNoAuthenticationIsUnauthorized() throws Exception {
    String totp = "123456";

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testDisableAuthenticatorAppPreAuthenticationIsUnauthorized() throws Exception {
    String totp = "654321";

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().isUnauthorized());
  }
}
