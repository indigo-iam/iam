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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationEventPublisher;

import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import it.infn.mw.iam.api.account.multi_factor_authentication.DefaultIamTotpRecoveryCodeResetService;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@SpringBootTest
class DefaultIamTotpRecoveryCodeResetServiceTests extends MultiFactorTestSupport {

  @Autowired
  private IamTotpMfaProperties iamTotpMfaProperties;

  @MockBean
  private IamAccountRepository accountRepository;

  @MockBean
  private IamTotpMfaRepository repository;

  @MockBean
  private RecoveryCodeGenerator recoveryCodeGenerator;

  @MockBean
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  private DefaultIamTotpRecoveryCodeResetService recoveryCodeResetService;

  @BeforeEach
  public void setUp() {
    // Only place(Test Class) to define and set password
    iamTotpMfaProperties.setPasswordToEncryptAndDecrypt(KEY_TO_ENCRYPT_DECRYPT);
  }

  @Test
  public void testEditMultiFactorSettingsIsEnabled() {
    /**
     * Admin hasn't defined true for the edit multi-factor settings
     * button to be visible.
     */
    assertFalse(iamTotpMfaProperties.isEditMultiFactorSettingsBtnEnabled());
  }

  @Test
  public void testResetRecoveryCodes_WithNoMultiFactorSecretAttached() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    MfaSecretNotFoundException thrownException = assertThrows(MfaSecretNotFoundException.class, () -> {
      recoveryCodeResetService.resetRecoveryCodes(account);
    });

    assertTrue(thrownException.getMessage().startsWith("No multi-factor secret is attached"));
  }

}
