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

public class RemoveOrphanTokens implements SpringJdbcFlywayMigration {

  public static final Logger LOG = LoggerFactory.getLogger(RemoveOrphanTokens.class);

  private static final String SAVED_AUTH_IDS_OF_DELETED_USERS =
      "SELECT id FROM saved_user_auth WHERE name NOT IN (SELECT username FROM iam_account)";

  private static final String DELETE_ACCESS_TOKENS_OF_DELETED_USERS =
      "DELETE FROM access_token WHERE auth_holder_id IN (" + SAVED_AUTH_IDS_OF_DELETED_USERS + ")";

  private static final String DELETE_REFRESH_TOKENS_OF_DELETED_USERS =
      "DELETE FROM refresh_token WHERE auth_holder_id IN (" + SAVED_AUTH_IDS_OF_DELETED_USERS + ")";

  private static final String DELETE_ACCESS_TOKENS_WITH_INVALID_AUTH_HOLDER =
      "DELETE FROM access_token WHERE auth_holder_id NOT IN (SELECT id FROM authentication_holder)";

  private static final String DELETE_REFRESH_TOKENS_WITH_INVALID_AUTH_HOLDER =
      "DELETE FROM refresh_token WHERE auth_holder_id NOT IN (SELECT id FROM authentication_holder)";

  @Override
  public void migrate(JdbcTemplate jdbcTemplate) throws DataAccessException {

    int updateResult = jdbcTemplate.update(DELETE_ACCESS_TOKENS_OF_DELETED_USERS);
    LOG.info("Removed {} access tokens owned by deleted users", updateResult);

    updateResult = jdbcTemplate.update(DELETE_REFRESH_TOKENS_OF_DELETED_USERS);
    LOG.info("Removed {} refresh tokens owned by deleted users", updateResult);

    updateResult = jdbcTemplate.update(DELETE_ACCESS_TOKENS_WITH_INVALID_AUTH_HOLDER);
    LOG.info("Removed {} access tokens with invalid authentication holder", updateResult);

    updateResult = jdbcTemplate.update(DELETE_REFRESH_TOKENS_WITH_INVALID_AUTH_HOLDER);
    LOG.info("Removed {} refresh tokens with invalid authentication holder", updateResult);
  }

}
