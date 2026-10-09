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
package it.infn.mw.iam.persistence.migrations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

public class RemoveDanglingDeviceCodes implements SpringJdbcFlywayMigration {

  public static final Logger LOG = LoggerFactory.getLogger(RemoveDanglingDeviceCodes.class);

  // Approved device codes whose authentication holder is missing: either never set or
  // deleted by the orphaned authentication holder cleanup (device_code.auth_holder_id has no FK)
  private static final String DANGLING_DEVICE_CODE_IDS =
      "SELECT id FROM device_code WHERE approved = 1 AND (auth_holder_id IS NULL"
          + " OR auth_holder_id NOT IN (SELECT id FROM authentication_holder))";

  private static final String DELETE_DANGLING_DEVICE_CODE_SCOPES =
      "DELETE FROM device_code_scope WHERE owner_id IN (" + DANGLING_DEVICE_CODE_IDS + ")";

  private static final String DELETE_DANGLING_DEVICE_CODE_REQUEST_PARAMETERS =
      "DELETE FROM device_code_request_parameter WHERE owner_id IN (" + DANGLING_DEVICE_CODE_IDS
          + ")";

  private static final String DELETE_DANGLING_DEVICE_CODES =
      "DELETE FROM device_code WHERE id IN (SELECT id FROM (" + DANGLING_DEVICE_CODE_IDS
          + ") AS dangling)";

  @Override
  public void migrate(JdbcTemplate jdbcTemplate) throws DataAccessException {

    jdbcTemplate.update(DELETE_DANGLING_DEVICE_CODE_SCOPES);
    jdbcTemplate.update(DELETE_DANGLING_DEVICE_CODE_REQUEST_PARAMETERS);

    int deleted = jdbcTemplate.update(DELETE_DANGLING_DEVICE_CODES);
    if (deleted > 0) {
      LOG.info("Removed {} dangling device codes (approved but with missing authentication holder)",
          deleted);
    }
  }

}
