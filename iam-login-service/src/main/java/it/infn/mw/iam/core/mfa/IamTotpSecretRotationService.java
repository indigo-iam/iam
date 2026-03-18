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
package it.infn.mw.iam.core.mfa;

import static it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil.decryptSecret;
import static it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret;

import java.util.Optional;

import org.flywaydb.core.internal.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamTotpAdminKey;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamTotpAdminKeyRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;

@Service
@Profile("mfa")
public class IamTotpSecretRotationService {

  private static final Logger LOG = LoggerFactory.getLogger(IamTotpSecretRotationService.class);

  private final IamTotpMfaProperties mfaProperties;
  private final IamTotpMfaRepository totpRepository;
  private final IamTotpAdminKeyRepository adminKeyRepository;
  private final PasswordEncoder passwordEncoder;

  public IamTotpSecretRotationService(IamTotpMfaProperties mfaProperties,
      IamTotpMfaRepository totpRepository, IamTotpAdminKeyRepository adminKeyRepository,
      PasswordEncoder passwordEncoder) {

    this.mfaProperties = mfaProperties;
    this.totpRepository = totpRepository;
    this.adminKeyRepository = adminKeyRepository;
    this.passwordEncoder = passwordEncoder;
    validate();
  }

  private void validate() {

    if (!StringUtils.hasText(mfaProperties.getPasswordToEncryptAndDecrypt())) {
      throw new IamTotpMfaInvalidArgumentError(
          "TOTP MFA: A password to encrypt mfa secrets is required");
    }
    Optional<IamTotpAdminKey> adminKey = adminKeyRepository.findAll().stream().findAny();
    if (adminKey.isEmpty()) {
      return;
    }
    String currentHash = adminKey.get().getAdminMfaKeyHash();
    if (passwordEncoder.matches(mfaProperties.getPasswordToEncryptAndDecrypt(), currentHash)) {
      return;
    }
    if (StringUtils.hasText(mfaProperties.getOldPasswordToDecrypt())
        && passwordEncoder.matches(mfaProperties.getOldPasswordToDecrypt(), currentHash)) {
      return;
    }
    throw new IamTotpMfaInvalidArgumentError(
        "TOTP MFA: Admin key changed. You MUST provide old password to re-encrypt existing secrets.");
  }

  public boolean shouldRotateSecrets() {

    IamTotpAdminKey adminKey = getCurrentKey();
    return !passwordEncoder.matches(mfaProperties.getPasswordToEncryptAndDecrypt(),
        adminKey.getAdminMfaKeyHash());
  }

  @Transactional(rollbackFor = Throwable.class)
  public void rotateSecrets() {

    validateProperties();
    totpRepository.findAll().stream().forEach(this::rotateSecret);
    IamTotpAdminKey adminKey =
        new IamTotpAdminKey(passwordEncoder.encode(mfaProperties.getPasswordToEncryptAndDecrypt()));
    adminKeyRepository.save(adminKey);
  }

  private void validateProperties() {

    if (!StringUtils.hasText(mfaProperties.getOldPasswordToDecrypt())) {
      throw new IamTotpMfaInvalidArgumentError(
          "A value for mfa.old-password-to-decrypt MUST be provided.");
    }
  }

  private void rotateSecret(IamTotpMfa totp) {

    final String rawSecret =
        decryptSecret(totp.getSecret(), mfaProperties.getOldPasswordToDecrypt());
    final String encrypted =
        encryptSecret(rawSecret, mfaProperties.getPasswordToEncryptAndDecrypt());
    totp.setSecret(encrypted);
    totpRepository.save(totp);
    LOG.info("TOTP MFA: Re-encrypted secret for id={}", totp.getId());
  }

  private IamTotpAdminKey getCurrentKey() {

    Optional<IamTotpAdminKey> current = adminKeyRepository.findAll().stream().findFirst();
    if (current.isEmpty()) {
      return initEncryptionKeyFromConfig();
    }
    return current.get();
  }

  private IamTotpAdminKey initEncryptionKeyFromConfig() {

    IamTotpAdminKey entity =
        new IamTotpAdminKey(passwordEncoder.encode(mfaProperties.getPasswordToEncryptAndDecrypt()));
    return adminKeyRepository.save(entity);
  }

}
