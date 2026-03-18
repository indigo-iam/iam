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
package it.infn.mw.iam.test.core.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.mfa.IamTotpSecretRotationService;
import it.infn.mw.iam.persistence.model.IamTotpAdminKey;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamTotpAdminKeyRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;

@ExtendWith(MockitoExtension.class)
class IamTotpMfaKeyRotationTests {

  @Mock
  private IamTotpMfaProperties mfaProperties;

  @Mock
  private IamTotpMfaRepository totpRepository;

  @Mock
  private IamTotpAdminKeyRepository adminKeyRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  final String currentKey = "define-new-key";
  final String oldKey = "define-old-key";
  final String storedHash = "stored-hash";

  private IamTotpSecretRotationService getService() {

    return new IamTotpSecretRotationService(mfaProperties, totpRepository, adminKeyRepository,
        passwordEncoder);
  }

  @Test
  void shouldRotateSecretsReturnsTrueWhenPasswordChanged() {

    IamTotpAdminKey adminKey = new IamTotpAdminKey("hash");

    when(adminKeyRepository.findAll()).thenReturn(List.of(adminKey));

    when(mfaProperties.getPasswordToEncryptAndDecrypt()).thenReturn("new-password");

    when(passwordEncoder.matches("new-password", "hash")).thenReturn(false);

    boolean result = getService().shouldRotateSecrets();

    assertTrue(result);
  }

  @Test
  void shouldRotateSecretsReturnsFalseWhenPasswordMatches() {

    IamTotpAdminKey adminKey = new IamTotpAdminKey("hash");

    when(adminKeyRepository.findAll()).thenReturn(List.of(adminKey));
    when(mfaProperties.getPasswordToEncryptAndDecrypt()).thenReturn("password");

    when(passwordEncoder.matches("password", "hash")).thenReturn(true);

    boolean result = getService().shouldRotateSecrets();

    assertFalse(result);
  }

  @Test
  void rotateAllSecrets() {

    String oldPassword = "oldPass";
    String newPassword = "newPass";
    String rawSecret = "MYSECRET";

    String encryptedWithOld =
        IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(rawSecret, oldPassword);

    IamTotpMfa totp = new IamTotpMfa();
    totp.setId(1L);
    totp.setSecret(encryptedWithOld);

    when(mfaProperties.getOldPasswordToDecrypt()).thenReturn(oldPassword);
    when(mfaProperties.getPasswordToEncryptAndDecrypt()).thenReturn(newPassword);

    when(totpRepository.findAll()).thenReturn(List.of(totp));

    when(passwordEncoder.encode(newPassword)).thenReturn("encoded");

    getService().rotateSecrets();

    verify(totpRepository).save(totp);
    verify(adminKeyRepository).save(any(IamTotpAdminKey.class));

    String decrypted =
        IamTotpMfaEncryptionAndDecryptionUtil.decryptSecret(totp.getSecret(), newPassword);

    assertEquals(rawSecret, decrypted);
  }

  @Test
  void validationExceptionWhenOldPasswordIsMissing() {

    assertThrows(IamTotpMfaInvalidArgumentError.class, () -> getService().rotateSecrets());
  }
}
