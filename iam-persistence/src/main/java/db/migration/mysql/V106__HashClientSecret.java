/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2018
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
package db.migration.mysql;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.rowset.SqlRowSet;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


import it.infn.mw.iam.persistence.migrations.BaseFlywayJavaMigrationAdapter;

public class V106__HashClientSecret extends BaseFlywayJavaMigrationAdapter {

  @Override
  public void migrate(JdbcTemplate jdbcTemplate) throws DataAccessException {

    final short DEFAULT_ROUND = 12;

    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(DEFAULT_ROUND);

    SqlRowSet clientList = jdbcTemplate.queryForRowSet("SELECT id, client_secret FROM client_details");

    while (clientList.next()) {
      String clientSecret = clientList.getString("client_secret");
      if (clientSecret == null) {
        continue;
      }
      Long id = clientList.getLong("id");

      String PassEncrypted = passwordEncoder.encode(clientSecret);

      if (passwordEncoder.matches(clientSecret, PassEncrypted)) {
        jdbcTemplate.update("UPDATE client_details SET client_secret=? WHERE id=?", PassEncrypted, id);
      }
    }
  }

}