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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.mfa.IamTotpSecretRotationService;
import it.infn.mw.iam.core.user.IamBCryptPasswordEncoder;
import it.infn.mw.iam.persistence.model.IamTotpAdminKey;
import it.infn.mw.iam.persistence.repository.IamTotpAdminKeyRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

class IamTotpPasswordLengthTests {
  private final IamTotpMfaProperties properties = new IamTotpMfaProperties();
  private final IamTotpAdminKeyRepository keys = mock(IamTotpAdminKeyRepository.class);
  private final IamTotpMfaRepository secrets = mock(IamTotpMfaRepository.class);
  private final PasswordEncoder encoder = new IamBCryptPasswordEncoder();
  private final ApplicationContextRunner runner =
      new ApplicationContextRunner().withUserConfiguration(IamTotpSecretRotationService.class)
        .withBean(IamTotpMfaProperties.class, () -> properties)
        .withBean(IamTotpAdminKeyRepository.class, () -> keys)
        .withBean(IamTotpMfaRepository.class, () -> secrets)
        .withBean(PasswordEncoder.class, () -> encoder);

  @Test
  void missingOrLongSecretDoesNotPreventStartupWithoutMfa() {
    runner.run(context -> assertThat(context).hasNotFailed()
      .doesNotHaveBean(IamTotpSecretRotationService.class));
    properties.setPasswordToEncryptAndDecrypt("é".repeat(37));
    runner.run(context -> assertThat(context).hasNotFailed()
      .doesNotHaveBean(IamTotpSecretRotationService.class));
    verifyNoInteractions(keys, secrets);
  }

  @Test
  void rejectsMissingSecretWhenMfaIsActive() {
    runner.withPropertyValues("spring.profiles.active=mfa")
      .run(context -> assertThat(context).hasFailed());
    verifyNoInteractions(keys, secrets);
  }

  @Test
  void rejectsLongSecretBeforeDatabaseAccessAndDoesNotExposeIt() {
    String secret = "é".repeat(37);
    properties.setPasswordToEncryptAndDecrypt(secret);
    runner.withPropertyValues("spring.profiles.active=mfa").run(context -> {
      assertThat(context).hasFailed();
      assertThat(context.getStartupFailure())
        .hasStackTraceContaining(
            "mfa.password-to-encrypt-and-decrypt must not exceed 72 UTF-8 bytes")
        .hasStackTraceContaining("Do not truncate")
        .hasStackTraceContaining("previous IAM version");
      assertThat(context.getStartupFailure()).hasStackTraceContaining("72")
        .hasMessageNotContaining(secret);
    });
    verifyNoInteractions(keys, secrets);
  }

  @Test
  void acceptsExactly72Utf8Bytes() {
    properties.setPasswordToEncryptAndDecrypt("é".repeat(36));
    runner.withPropertyValues("spring.profiles.active=mfa")
      .run(context -> assertThat(context).hasNotFailed()
        .hasSingleBean(IamTotpSecretRotationService.class));
    verifyNoInteractions(secrets);
  }

  @Test
  void rejectsOversizedOldKeyWithMigrationInstructions() {
    properties.setPasswordToEncryptAndDecrypt("new-secret");
    properties.setOldPasswordToDecrypt("a".repeat(73));
    when(keys.findAll()).thenReturn(List.of(new IamTotpAdminKey(encoder.encode("old-secret"))));
    runner.withPropertyValues("spring.profiles.active=mfa").run(context -> {
      assertThat(context).hasFailed();
      assertThat(context.getStartupFailure())
        .hasStackTraceContaining("mfa.old-password-to-decrypt exceeds 72 UTF-8 bytes");
    });
    verifyNoInteractions(secrets);
    verify(keys, never()).save(any());
  }

  @Test
  void ignoresUnusedOldKeyWhenCurrentKeyMatches() {
    properties.setPasswordToEncryptAndDecrypt("current-secret");
    properties.setOldPasswordToDecrypt("a".repeat(73));
    when(keys.findAll()).thenReturn(List.of(new IamTotpAdminKey(encoder.encode("current-secret"))));
    runner.withPropertyValues("spring.profiles.active=mfa")
      .run(context -> assertThat(context).hasNotFailed()
        .hasSingleBean(IamTotpSecretRotationService.class));
  }
}
