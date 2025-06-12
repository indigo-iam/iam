/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2025
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

package it.infn.mw.iam.persistence.migrations;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import org.yaml.snakeyaml.Yaml;

import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

public class UpdateSecretKeysMFA implements SpringJdbcFlywayMigration {

  public static final Logger LOG = LoggerFactory.getLogger(UpdateSecretKeysMFA.class);

  @Override
  public void migrate(JdbcTemplate jdbcTemplate) throws DataAccessException {
    // Read env and system properties
    String updateKeyRequest = System.getenv("IAM_TOTP_MFA_UPDATE_GLOBAL_KEY_REQUEST");
    String oldPassword = System.getenv("IAM_TOTP_MFA_OLD_PASSWORD_TO_DECRYPT");
    String newPassword = System.getenv("IAM_TOTP_MFA_PASSWORD_TO_ENCRYPT_AND_DECRYPT");

    if (oldPassword == null || oldPassword.isEmpty()) {
      oldPassword = System.getProperty("mfa.old-password-to-decrypt");
    }
    if (newPassword == null || newPassword.isEmpty()) {
      newPassword = System.getProperty("mfa.password-to-encrypt-and-decrypt");
    }
    if (updateKeyRequest == null || updateKeyRequest.isEmpty()) {
      updateKeyRequest = System.getProperty("mfa.update-global-key-request");
    }

    // Fallback to YAML if needed
    if (oldPassword == null || newPassword == null || updateKeyRequest == null ||
        oldPassword.isEmpty() || newPassword.isEmpty() || updateKeyRequest.isEmpty()) {

      LOG.warn("Trying to read fallback from application-mfa.yml because env/system props are missing...");

      try (InputStream in = getClass().getClassLoader().getResourceAsStream("application-mfa.yml")) {
        if (in != null) {
          Yaml yaml = new Yaml();
          Map<String, Object> yamlData = yaml.load(in);

          Map<String, Object> mfa = (Map<String, Object>) yamlData.get("mfa");
          if (mfa != null) {
            if ((oldPassword == null || oldPassword.isEmpty()) && mfa.get("old-password-to-decrypt") != null) {
              oldPassword = extractFallbackFromPlaceholder((String) mfa.get("old-password-to-decrypt"));
            }
            if ((newPassword == null || newPassword.isEmpty()) && mfa.get("password-to-encrypt-and-decrypt") != null) {
              newPassword = extractFallbackFromPlaceholder((String) mfa.get("password-to-encrypt-and-decrypt"));
            }
            if ((updateKeyRequest == null || updateKeyRequest.isEmpty()) && mfa.get("update-global-key-request") != null) {
              updateKeyRequest = extractFallbackFromPlaceholder((String) mfa.get("update-global-key-request"));
            }
          }
        } else {
          LOG.warn("application-mfa.yml not found in classpath.");
        }
      } catch (Exception e) {
        LOG.error("Error reading application-mfa.yml: {}", e.getMessage(), e);
      }
    }

    // Run ONLY if update-global-key-request is "true" else return(do nothing)
    if (!Boolean.parseBoolean(updateKeyRequest)) {
      LOG.info("Migration skipped because update-global-key-request is not set to true.");
      return;
    }

    // Abort if passwords are missing
    if (oldPassword == null || oldPassword.isEmpty() || newPassword == null || newPassword.isEmpty()) {
      LOG.error("Old or New encryption password is missing. Aborting migration.");
      return;
    }

    LOG.info("Starting migration with resolved oldPassword and newPassword...");

    List<Map<String, Object>> secrets = jdbcTemplate.queryForList("SELECT id, secret FROM iam_totp_mfa");

    for (Map<String, Object> entry : secrets) {
      Long id = (Long) entry.get("id");
      String encryptedSecret = (String) entry.get("secret");

      try {
        String decryptedSecret = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecret(encryptedSecret, oldPassword);
        String reEncryptedSecret = IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(decryptedSecret, newPassword);

        jdbcTemplate.update("UPDATE iam_totp_mfa SET secret = ? WHERE id = ?", reEncryptedSecret, id);

        LOG.info("Successfully updated secret for id {}", id);
      } catch (Exception e) {
        LOG.error("Failed to re-encrypt secret for id {}: {}", id, e.getMessage(), e);
      }
    }

    LOG.info("Secret key migration completed successfully.");
  }

  private String extractFallbackFromPlaceholder(String raw) {
    if (raw == null) {
      return null;
    }
    Pattern pattern = Pattern.compile("\\$\\{[^:]+:(.+)}");
    Matcher matcher = pattern.matcher(raw);
    if (matcher.matches()) {
      return matcher.group(1);
    }
    return raw; // no placeholder found, return as-is
  }
}
