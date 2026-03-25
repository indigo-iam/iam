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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.NestedServletException;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.user.exception.MfaSecretAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.core.user.exception.TotpMfaAlreadyEnabledException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockMfaUser;
import it.infn.mw.iam.test.util.WithMockPreAuthenticatedUser;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class AuthenticatorAppSettingsControllerTests extends MultiFactorTestSupport {

  @Autowired
  private MockMvc mvc;

  @MockBean
  private IamAccountRepository accountRepository;

  @MockBean
  private IamTotpMfaService totpMfaService;

  @MockBean
  private IamTotpMfaProperties iamTotpMfaProperties;

  Clock clock;
  IamAccount mfaAccount;
  IamTotpMfa totpMfa;

  @BeforeEach
  void setup() {

    clock = Clock.systemUTC();
    mfaAccount = getTotpMfaAccount(clock.instant());
    totpMfa = getTotpMfaFor(mfaAccount, clock.instant());
    Mockito.when(accountRepository.findByUsername(mfaAccount.getUsername()))
      .thenReturn(Optional.of(mfaAccount));
    Mockito.when(iamTotpMfaProperties.getPasswordToEncryptAndDecrypt())
      .thenReturn(KEY_TO_ENCRYPT_DECRYPT);
  }

  @Test
  @WithMockMfaUser
  void testAddSecret() throws Exception {

    totpMfa.setActive(false);
    totpMfa.setAccount(null);
    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        iamTotpMfaProperties.getPasswordToEncryptAndDecrypt()));
    Mockito.when(totpMfaService.addTotpMfaSecret(mfaAccount)).thenReturn(totpMfa);

    mvc.perform(put(ADD_SECRET_URL)).andExpect(status().isOk());

    Mockito.verify(accountRepository, times(2)).findByUsername(TOTP_USERNAME);
    Mockito.verify(totpMfaService, times(1)).addTotpMfaSecret(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testAddSecretThrowsMfaSecretAlreadyBoundException() throws Exception {

    totpMfa.setActive(false);
    totpMfa.setAccount(null);
    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        iamTotpMfaProperties.getPasswordToEncryptAndDecrypt()));
    Mockito.when(totpMfaService.addTotpMfaSecret(mfaAccount))
      .thenThrow(new MfaSecretAlreadyBoundException(
          "A multi-factor secret is already assigned to this account"));

    mvc.perform(put(ADD_SECRET_URL)).andExpect(status().isConflict());

    Mockito.verify(accountRepository, times(2)).findByUsername(TOTP_USERNAME);
    Mockito.verify(totpMfaService, times(1)).addTotpMfaSecret(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testAddSecret_withEmptyPassword() throws Exception {

    totpMfa.setActive(false);
    totpMfa.setAccount(null);
    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        iamTotpMfaProperties.getPasswordToEncryptAndDecrypt()));

    Mockito.when(totpMfaService.addTotpMfaSecret(mfaAccount)).thenReturn(totpMfa);
    Mockito.when(iamTotpMfaProperties.getPasswordToEncryptAndDecrypt()).thenReturn("");

    NestedServletException thrownException = assertThrows(NestedServletException.class, () -> {
      mvc.perform(put(ADD_SECRET_URL));
    });

    assertTrue(
        thrownException.getCause().getMessage().startsWith("Please ensure that you provide"));
  }

  @Test
  @WithAnonymousUser
  void testAddSecretNoAuthenticationIsUnauthorized() throws Exception {
    mvc.perform(put(ADD_SECRET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  void testAddSecretPreAuthenticationIsUnauthorized() throws Exception {
    mvc.perform(put(ADD_SECRET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockMfaUser
  void testEnableAuthenticatorApp() throws Exception {

    totpMfa.setActive(true);
    totpMfa.setAccount(mfaAccount);
    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        iamTotpMfaProperties.getPasswordToEncryptAndDecrypt()));
    String totp = "123456";

    Mockito.when(totpMfaService.verifyTotp(mfaAccount, totp)).thenReturn(true);
    Mockito.when(totpMfaService.enableTotpMfa(mfaAccount)).thenReturn(totpMfa);

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().isOk());

    Mockito.verify(accountRepository, times(2)).findByUsername(TOTP_USERNAME);
    Mockito.verify(totpMfaService, times(1)).verifyTotp(mfaAccount, totp);
    Mockito.verify(totpMfaService, times(1)).enableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testEnableAuthenticatorAppThrowsTotpMfaAlreadyEnabledException() throws Exception {

    String totp = "123456";

    Mockito.when(totpMfaService.verifyTotp(mfaAccount, totp)).thenReturn(true);
    Mockito.when(totpMfaService.enableTotpMfa(mfaAccount))
      .thenThrow(new TotpMfaAlreadyEnabledException("TOTP MFA is already enabled on this account"));

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().isConflict());

    Mockito.verify(accountRepository, times(2)).findByUsername(TOTP_USERNAME);
    Mockito.verify(totpMfaService, times(1)).verifyTotp(mfaAccount, totp);
    Mockito.verify(totpMfaService, times(1)).enableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testEnableAuthenticatorAppIncorrectCode() throws Exception {

    String totp = "123456";

    Mockito.when(totpMfaService.verifyTotp(mfaAccount, totp)).thenReturn(false);

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    Mockito.verify(totpMfaService, times(1)).verifyTotp(mfaAccount, totp);
    Mockito.verify(totpMfaService, never()).enableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testEnableAuthenticatorAppButTotpVerificationFails() throws Exception {

    String totp = "123456";

    Mockito.when(totpMfaService.verifyTotp(mfaAccount, totp))
      .thenThrow(new MfaSecretNotFoundException(MFA_SECRET_NOT_FOUND_MESSAGE));

    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    Mockito.verify(totpMfaService, times(1)).verifyTotp(mfaAccount, totp);
    Mockito.verify(totpMfaService, never()).enableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testEnableAuthenticatorAppInvalidCharactersInCode() throws Exception {

    String totp = "abcdef";
    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());
    Mockito.verify(totpMfaService, never()).enableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testEnableAuthenticatorAppCodeTooShort() throws Exception {

    String totp = "12345";
    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());
    Mockito.verify(totpMfaService, never()).enableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testEnableAuthenticatorAppCodeTooLong() throws Exception {

    String totp = "1234567";
    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());
    Mockito.verify(totpMfaService, never()).enableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testEnableAuthenticatorAppNullCode() throws Exception {

    String totp = null;
    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());
    Mockito.verify(totpMfaService, never()).enableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testEnableAuthenticatorAppEmptyCode() throws Exception {

    String totp = "";
    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());
    Mockito.verify(totpMfaService, never()).enableTotpMfa(mfaAccount);
  }

  @Test
  @WithAnonymousUser
  void testEnableAuthenticatorAppNoAuthenticationIsUnauthorized() throws Exception {

    String totp = "123456";
    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  void testEnableAuthenticatorAppPreAuthenticationIsUnauthorized() throws Exception {

    String totp = "654321";
    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockMfaUser
  void testDisableAuthenticatorApp() throws Exception {

    String totp = "123456";

    Mockito.when(totpMfaService.verifyTotp(mfaAccount, totp)).thenReturn(true);
    Mockito.when(totpMfaService.disableTotpMfa(mfaAccount)).thenReturn(totpMfa);

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().isOk());

    Mockito.verify(accountRepository, times(2)).findByUsername(TOTP_USERNAME);
    Mockito.verify(totpMfaService, times(1)).verifyTotp(mfaAccount, totp);
    Mockito.verify(totpMfaService, times(1)).disableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testDisableAuthenticatorAppIncorrectCode() throws Exception {

    String totp = "123456";

    Mockito.when(totpMfaService.verifyTotp(mfaAccount, totp)).thenReturn(false);

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    Mockito.verify(totpMfaService, times(1)).verifyTotp(mfaAccount, totp);
    Mockito.verify(totpMfaService, never()).disableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testDisableAuthenticatorAppButTotpVerificationFails() throws Exception {

    String totp = "123456";

    Mockito.when(totpMfaService.verifyTotp(mfaAccount, totp))
      .thenThrow(new MfaSecretNotFoundException(MFA_SECRET_NOT_FOUND_MESSAGE));

    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());

    Mockito.verify(totpMfaService, times(1)).verifyTotp(mfaAccount, totp);
    Mockito.verify(totpMfaService, never()).disableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testDisableAuthenticatorAppInvalidCharactersInCode() throws Exception {

    String totp = "123456";
    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());
    Mockito.verify(totpMfaService, never()).disableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testDisableAuthenticatorAppCodeTooShort() throws Exception {

    String totp = "12345";
    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());
    Mockito.verify(totpMfaService, never()).disableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testDisableAuthenticatorAppCodeTooLong() throws Exception {

    String totp = "1234567";
    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());
    Mockito.verify(totpMfaService, never()).disableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testDisableAuthenticatorAppNullCode() throws Exception {

    String totp = null;
    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());
    Mockito.verify(totpMfaService, never()).disableTotpMfa(mfaAccount);
  }

  @Test
  @WithMockMfaUser
  void testDisableAuthenticatorAppEmptyCode() throws Exception {

    String totp = "";
    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().is4xxClientError());
    Mockito.verify(totpMfaService, never()).disableTotpMfa(mfaAccount);
  }

  @Test
  @WithAnonymousUser
  void testDisableAuthenticatorAppNoAuthenticationIsUnauthorized() throws Exception {

    String totp = "123456";
    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  void testDisableAuthenticatorAppPreAuthenticationIsUnauthorized() throws Exception {

    String totp = "654321";
    mvc.perform(post(DISABLE_URL).param("code", totp)).andExpect(status().isUnauthorized());
  }
}
