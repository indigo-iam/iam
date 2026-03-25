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
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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

import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrGenerator;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class AuthenticationAppSettingsTotpTests extends MultiFactorTestSupport {

  @Autowired
  private MockMvc mvc;

  @MockBean
  private IamAccountRepository accountRepository;

  @MockBean
  private IamTotpMfaService totpMfaService;

  @MockBean
  private IamTotpMfaProperties iamTotpMfaProperties;

  @MockBean
  private QrGenerator qrGenerator;

  Clock clock;
  IamAccount mfaAccount;
  IamTotpMfa totpMfa;

  @BeforeEach
  void setup() {

    clock = Clock.systemUTC();
    mfaAccount = getTotpMfaAccount(clock.instant());
    totpMfa = getTotpMfaFor(mfaAccount, clock.instant());
    when(accountRepository.findByUsername(mfaAccount.getUsername())).thenReturn(Optional.of(mfaAccount));
    when(iamTotpMfaProperties.getPasswordToEncryptAndDecrypt()).thenReturn(KEY_TO_ENCRYPT_DECRYPT);
  }

  @Test
  @WithMockUser(username = TOTP_USERNAME)
  void testAddSecretThrowsQrGenerationException() throws Exception {

    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        iamTotpMfaProperties.getPasswordToEncryptAndDecrypt()));
    Mockito.when(totpMfaService.addTotpMfaSecret(mfaAccount)).thenReturn(totpMfa);

    Mockito.when(totpMfaService.generateQRCodeFromSecret(TOTP_MFA_SECRET, TOTP_USERNAME)).thenThrow(
        new QrGenerationException("Simulated QR generation failure", new RuntimeException()));

    mvc.perform(put(ADD_SECRET_URL))
      .andExpect(status().isBadRequest())
      .andExpect(content().string(containsString("Could not generate QR code")));

    Mockito.verify(accountRepository, times(2)).findByUsername(TOTP_USERNAME);
    Mockito.verify(totpMfaService, times(1)).addTotpMfaSecret(mfaAccount);
    Mockito.verify(totpMfaService, times(1)).generateQRCodeFromSecret(TOTP_MFA_SECRET, TOTP_USERNAME);
  }

  @Test
  @WithMockOAuthUser(user = TOTP_USERNAME, authorities = "ROLE_USER")
  void testEnableAuthenticatorAppViaOauthAuthn() throws Exception {

    String totp = "123456";

    Mockito.when(totpMfaService.verifyTotp(mfaAccount, totp)).thenReturn(true);
    Mockito.when(totpMfaService.enableTotpMfa(mfaAccount)).thenReturn(totpMfa);

    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        iamTotpMfaProperties.getPasswordToEncryptAndDecrypt()));
    mvc.perform(post(ENABLE_URL).param("code", totp)).andExpect(status().isOk());

    Mockito.verify(accountRepository, times(2)).findByUsername(TOTP_USERNAME);
    Mockito.verify(totpMfaService, times(1)).verifyTotp(mfaAccount, totp);
    Mockito.verify(totpMfaService, times(1)).enableTotpMfa(mfaAccount);
  }
}
