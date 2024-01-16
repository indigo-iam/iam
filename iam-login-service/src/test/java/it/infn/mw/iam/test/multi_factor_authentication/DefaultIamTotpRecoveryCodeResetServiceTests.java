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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationEventPublisher;

import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import it.infn.mw.iam.api.account.multi_factor_authentication.DefaultIamTotpRecoveryCodeResetService;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaEncryptionAndDecryptionService;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;

@SpringBootTest
class DefaultIamTotpRecoveryCodeResetServiceTests extends MultiFactorTestSupport {

  @MockBean
  private IamAccountRepository accountRepository;

  @MockBean
  private IamTotpMfaRepository repository;

  @MockBean
  private RecoveryCodeGenerator recoveryCodeGenerator;

  @MockBean
  private IamTotpMfaEncryptionAndDecryptionService iamTotpMfaEncryptionAndDecryptionService;

  @MockBean
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  private DefaultIamTotpRecoveryCodeResetService recoveryCodeResetService;

  @BeforeEach
  public void setUp() {
    // Only place(Test Class) to define and set password
    when(iamTotpMfaEncryptionAndDecryptionService.hasAdminTriggeredTheJob()).thenReturn(false);
    when(iamTotpMfaEncryptionAndDecryptionService.whichPasswordToUseForEncryptAndDecrypt(anyLong(), anyBoolean())).thenReturn(KEY_TO_ENCRYPT_DECRYPT);
  }

  @Test
  public void testResetRecoveryCodes_WithNoMultiFactorSecretAttached() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    MfaSecretNotFoundException thrownException = assertThrows(MfaSecretNotFoundException.class, () -> {
      recoveryCodeResetService.resetRecoveryCodes(account);
    });

    assertTrue(thrownException.getMessage().startsWith("No multi-factor secret is attached"));
  }

  @Test
  public void testResetRecoveryCodes() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(TOTP_MFA));
    String[] testArray = { TOTP_RECOVERY_CODE_STRING_7, TOTP_RECOVERY_CODE_STRING_8,
        TOTP_RECOVERY_CODE_STRING_9, TOTP_RECOVERY_CODE_STRING_10, TOTP_RECOVERY_CODE_STRING_11,
        TOTP_RECOVERY_CODE_STRING_12 };
    when(recoveryCodeGenerator.generateCodes(anyInt())).thenReturn(testArray);

    IamAccount result = recoveryCodeResetService.resetRecoveryCodes(account);

    assertNotNull(result);
    verify(accountRepository, times(1)).save(account);
  }

  @Test
  public void testResetRecoveryCodes_WithEmptyPassword() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(TOTP_MFA));
    String[] testArray = { TOTP_RECOVERY_CODE_STRING_7, TOTP_RECOVERY_CODE_STRING_8,
        TOTP_RECOVERY_CODE_STRING_9, TOTP_RECOVERY_CODE_STRING_10, TOTP_RECOVERY_CODE_STRING_11,
        TOTP_RECOVERY_CODE_STRING_12 };
    when(recoveryCodeGenerator.generateCodes(anyInt())).thenReturn(testArray);

    IamTotpMfaInvalidArgumentError thrownException = assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
      recoveryCodeResetService.resetRecoveryCodes(account);
    });

    assertTrue(thrownException.getMessage().startsWith("Please ensure that you provide"));
  }
}
