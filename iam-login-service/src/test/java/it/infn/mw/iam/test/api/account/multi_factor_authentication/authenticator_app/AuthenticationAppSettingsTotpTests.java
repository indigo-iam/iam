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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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

import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class AuthenticationAppSettingsTotpTests extends MultiFactorTestSupport {

  private MockMvc mvc;

  @Autowired
  private WebApplicationContext context;

  @MockBean
  private IamAccountRepository accountRepository;

  @MockBean
  private IamTotpMfaService totpMfaService;

  @MockBean
  private IamTotpMfaProperties iamTotpMfaProperties;

  @MockBean
  private QrGenerator qrGenerator;


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
  public void testAddSecretThrowsQrGenerationException() throws Exception {
    IamAccount account = cloneAccount(TEST_ACCOUNT);
    when(accountRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(account));

    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);
    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()));
    when(totpMfaService.addTotpMfaSecret(account)).thenReturn(totpMfa);

    when(qrGenerator.generate(any(QrData.class))).thenThrow(
        new QrGenerationException("Simulated QR generation failure", new RuntimeException()));

    mvc.perform(put(ADD_SECRET_URL))
      .andExpect(status().isBadRequest())
      .andExpect(content().string(containsString("Could not generate QR code")));

    verify(accountRepository, times(2)).findByUsername(TEST_USERNAME);
    verify(totpMfaService, times(1)).addTotpMfaSecret(account);
    verify(qrGenerator, times(1)).generate(any(QrData.class));
  }
  
  @Test
  @WithMockOAuthUser(user = TEST_USERNAME, authorities = "ROLE_USER")
  public void testEnableAuthenticatorAppViaOauthAuthn() throws Exception {
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
}