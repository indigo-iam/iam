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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

class H2MigrationTests {

  @Test
  void migratesSchemaAndFixturesAndValidatesOnRestart() {
    String url =
        "jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=LEGACY;NON_KEYWORDS=VALUE;DB_CLOSE_DELAY=-1";
    DriverManagerDataSource dataSource = new DriverManagerDataSource(url, "sa", "");
    JdbcTemplate jdbc = new JdbcTemplate(dataSource);
    try {
      Flyway flyway = Flyway.configure()
        .dataSource(dataSource)
        .locations("classpath:db/migration/h2", "classpath:db/migration/test")
        .load();

      assertTrue(flyway.migrate().migrationsExecuted > 0);
      flyway.validate();
      assertEquals(0, flyway.migrate().migrationsExecuted);
      assertEquals(1, jdbc.queryForObject(
          "SELECT COUNT(*) FROM iam_account WHERE username = 'manager'", Integer.class));
      assertEquals(1,
          jdbc.queryForObject("SELECT COUNT(*) FROM iam_account a "
              + "JOIN iam_account_authority aa ON aa.account_id = a.id "
              + "JOIN iam_authority auth ON auth.id = aa.authority_id "
              + "WHERE a.username = 'manager' AND auth.auth LIKE 'ROLE_GM:%'", Integer.class));
    } finally {
      jdbc.execute("SET DB_CLOSE_DELAY 0");
    }
  }
}
