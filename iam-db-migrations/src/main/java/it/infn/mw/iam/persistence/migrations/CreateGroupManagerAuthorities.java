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
import org.springframework.jdbc.support.rowset.SqlRowSet;

public class CreateGroupManagerAuthorities implements SpringJdbcFlywayMigration {

  public static final Logger LOG = LoggerFactory.getLogger(CreateGroupManagerAuthorities.class);

  @Override
  public void migrate(JdbcTemplate jdbcTemplate) throws DataAccessException {
    SqlRowSet rowSet = jdbcTemplate.queryForRowSet("SELECT id,uuid,name from iam_group");

    while (rowSet.next()) {
      String authority = String.format("ROLE_GM:%s", rowSet.getString("uuid"));
      int updateResult =
          jdbcTemplate.update("insert into iam_authority(auth) values (?)", authority);
      if (updateResult == 1) {
        LOG.debug("Created group manager authority '{}' for group '{}'", authority,
            rowSet.getString("name"));
      }
    }
  }

}
