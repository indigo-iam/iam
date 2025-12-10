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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.infn.mw.iam.persistence.model.IamTotpAdminKey;
import it.infn.mw.iam.persistence.repository.IamTotpAdminKeyRepository;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;

/**
 * Runs at application startup (when the "mfa" profile is active) and ensures the
 * configured MFA admin key is recorded; if the key changed, it re-encrypts all
 * stored TOTP secrets using the old key -> And, encrypts it using new key.
 */
@Component
@Profile("mfa")
public class IamTotpMfaKeyRotationRunner implements ApplicationRunner {

  private static final Logger LOG = LoggerFactory.getLogger(IamTotpMfaKeyRotationRunner.class);

  /**
    * The current admin key used to encrypt/decrypt TOTP secrets.
    * MUST be provided when MFA is enabled.
  */
  @Value("${mfa.password-to-encrypt-and-decrypt}")
  private String currentMfaKey;

  /**
    * Optional previous admin key; required only when rotating to a new key so that
    * existing secrets can be re-encrypted.
  */
  @Value("${mfa.old-password-to-decrypt}")
  private String previousMfaKey;

  private final PasswordEncoder passwordEncoder;
  private final IamTotpAdminKeyRepository repository;
  private final IamTotpSecretRotationService iamTotpSecretRotationService;
  
 

  public IamTotpMfaKeyRotationRunner(
      IamTotpAdminKeyRepository repository,
      PasswordEncoder passwordEncoder,
      IamTotpSecretRotationService iamTotpSecretRotationService
      ) {
    this.repository = repository;
    this.passwordEncoder = passwordEncoder;
    this.iamTotpSecretRotationService = iamTotpSecretRotationService;
  }

  @Override
  public void run(ApplicationArguments args) {

    final String storedHash = repository.findCurrentHash();

    // First-time setup: require a key and store its hash
    if (storedHash == null) {
      if (!StringUtils.hasText(currentMfaKey)) {
        throw new IamTotpMfaInvalidArgumentError("TOTP MFA: A key MUST be provided to use MFA.");
      }
      repository.save(new IamTotpAdminKey(passwordEncoder.encode(currentMfaKey)));
      return;
    }

    // If unchanged, nothing to do
    if (passwordEncoder.matches(currentMfaKey, storedHash)) {
      // Do Nothing
      return;
    }

    // Rotation: need the previous key to re-encrypt existing secrets
    // If the previous key to re-encrypt existing secrets doesn't match storedHash; then it fails
    if (!StringUtils.hasText(previousMfaKey) || !passwordEncoder.matches(previousMfaKey, storedHash)) {
      throw new IamTotpMfaInvalidArgumentError(
        "TOTP MFA: Admin key changed. You MUST provide old password to re-encrypt existing secrets.");
    }

    LOG.info("TOTP MFA: Admin key changed. Starting TOTP secret re-encryption.");
    iamTotpSecretRotationService.reEncryptAllTotpSecrets(previousMfaKey, currentMfaKey);
  
    repository.save(new IamTotpAdminKey(passwordEncoder.encode(currentMfaKey)));
    LOG.info("TOTP MFA: Admin key rotation completed successfully.");
  }
}
