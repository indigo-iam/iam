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

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.test.util.ReflectionTestUtils;
import it.infn.mw.iam.core.mfa.IamTotpMfaKeyRotationRunner;
import it.infn.mw.iam.core.mfa.IamTotpSecretRotationService;
import it.infn.mw.iam.persistence.model.IamTotpAdminKey;
import it.infn.mw.iam.persistence.repository.IamTotpAdminKeyRepository;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

@ExtendWith(MockitoExtension.class)
class IamTotpMfaKeyRotationRunnerTests {

  @Mock IamTotpAdminKeyRepository repo;
  @Mock PasswordEncoder encoder;
  @Mock IamTotpSecretRotationService rotationService;

  // Instantiate and configure manually.
  IamTotpMfaKeyRotationRunner runner;

  final String currentKey = "define-new-key";
  final String oldKey = "define-old-key";
  final String storedHash = "stored-hash";

  @BeforeEach
  void init() {
    runner = new IamTotpMfaKeyRotationRunner(repo, encoder, rotationService);

    // Manually inject the @Value fields (Field Injection simulation)
    ReflectionTestUtils.setField(runner, "currentMfaKey", currentKey);
    ReflectionTestUtils.setField(runner, "previousMfaKey", oldKey);
  }

  @Test
  void storesInitialHashWhenNoneExists() {
    when(repo.findCurrentHash()).thenReturn(null);
    when(encoder.encode(currentKey)).thenReturn("encoded");

    runner.run(null);

    verify(repo).save(any(IamTotpAdminKey.class));
    verifyNoInteractions(rotationService);
  }

  @Test
  void failsIfInitialKeyIsMissing() {
    when(repo.findCurrentHash()).thenReturn(null);

    // Overwrite the field to be empty for this specific test
    ReflectionTestUtils.setField(runner, "currentMfaKey", "");

    assertThatThrownBy(() -> runner.run(null))
      .isInstanceOf(IamTotpMfaInvalidArgumentError.class)
      .hasMessageContaining("key MUST be provided");
  }

  @Test
  void skipsRotationIfKeyUnchanged() {
    when(repo.findCurrentHash()).thenReturn(storedHash);
    when(encoder.matches(currentKey, storedHash)).thenReturn(true);

    runner.run(null);

    verifyNoInteractions(rotationService);
    verify(repo, never()).save(any());
  }

  @Test
  void failsIfOldKeyMissingDuringRotation() {
    when(repo.findCurrentHash()).thenReturn(storedHash);
    when(encoder.matches(currentKey, storedHash)).thenReturn(false);

    // Overwrite the previous key to be empty
    ReflectionTestUtils.setField(runner, "previousMfaKey", "");

    assertThatThrownBy(() -> runner.run(null))
      .isInstanceOf(IamTotpMfaInvalidArgumentError.class)
      .hasMessageContaining("You MUST provide old password");
  }

  @Test
  void failsIfOldKeyDoesNotMatchStoredHash() {
    when(repo.findCurrentHash()).thenReturn(storedHash);
    when(encoder.matches(currentKey, storedHash)).thenReturn(false);
    
    // The key is present ("define-old-key"), but we mock it to NOT match
    when(encoder.matches(oldKey, storedHash)).thenReturn(false);

    assertThatThrownBy(() -> runner.run(null))
      .isInstanceOf(IamTotpMfaInvalidArgumentError.class)
      .hasMessageContaining("You MUST provide old password");
  }

  @Test
  void triggersRotationAndStoresNewHash() {
    when(repo.findCurrentHash()).thenReturn(storedHash);
    when(encoder.matches(currentKey, storedHash)).thenReturn(false);
    when(encoder.matches(oldKey, storedHash)).thenReturn(true);
    when(encoder.encode(currentKey)).thenReturn("encoded");

    runner.run(null);

    verify(rotationService).reEncryptAllTotpSecrets(oldKey, currentKey);
    verify(repo).save(any(IamTotpAdminKey.class));
  }

  @Test
  void spyRotationServiceExecutesRealReEncryptionLogic() {
    JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
    IamTotpSecretRotationService realService = spy(new IamTotpSecretRotationService(jdbcTemplate));
    
    // Instantiate runner with the SPY service
    IamTotpMfaKeyRotationRunner realRunner = new IamTotpMfaKeyRotationRunner(repo, encoder, realService);
    
    // Don't forget to inject fields into this new runner instance!
    ReflectionTestUtils.setField(realRunner, "currentMfaKey", currentKey);
    ReflectionTestUtils.setField(realRunner, "previousMfaKey", oldKey);

    String encryptedWithOldKey = 
        IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret("plain-secret", oldKey);
    Map<String, Object> row = Map.of("id", 1L, "secret", encryptedWithOldKey);

    when(repo.findCurrentHash()).thenReturn(storedHash);
    when(encoder.matches(currentKey, storedHash)).thenReturn(false);
    when(encoder.matches(oldKey, storedHash)).thenReturn(true);
    when(encoder.encode(currentKey)).thenReturn("encoded");

    when(jdbcTemplate.queryForList("SELECT id, secret FROM iam_totp_mfa"))
        .thenReturn(List.of(row));
    when(jdbcTemplate.update(anyString(), any(), anyLong())).thenReturn(1);

    realRunner.run(null);

    verify(realService).reEncryptAllTotpSecrets(oldKey, currentKey);
    verify(jdbcTemplate).update(startsWith("UPDATE iam_totp_mfa"), any(), eq(1L));
  }
}
