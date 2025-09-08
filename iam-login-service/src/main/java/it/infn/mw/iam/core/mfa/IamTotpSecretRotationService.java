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

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;

@Service
@Profile("mfa")
public class IamTotpSecretRotationService {

  private static final Logger LOG = LoggerFactory.getLogger(IamTotpSecretRotationService.class);

  private final JdbcTemplate jdbcTemplate;

  public IamTotpSecretRotationService(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @Transactional(rollbackFor = IamTotpMfaInvalidArgumentError.class)
  public void reEncryptAllTotpSecrets(String oldKey, String newKey) {
    List<Map<String, Object>> rows = jdbcTemplate.queryForList("SELECT id, secret FROM iam_totp_mfa");

    for (Map<String, Object> row : rows) {
      final long id = ((Number) row.get("id")).longValue();
      final String encryptedSecret = (String) row.get("secret");

      final String decrypted = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecret(encryptedSecret, oldKey);
      final String reEncrypted = IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(decrypted, newKey);
      jdbcTemplate.update("UPDATE iam_totp_mfa SET secret = ? WHERE id = ?", reEncrypted, id);
      LOG.info("TOTP MFA: Re-encrypted secret for id={}", id);
    }
  }
}
