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
package db.migration.postgresql_test;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.SQLException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import it.infn.mw.iam.core.Sha256Encoder;
import it.infn.mw.iam.persistence.migrations.MigrationTestDatabase;

class PostgresqlTestDataJavaMigrationsTests {

  private MigrationTestDatabase db;
  private JdbcTemplate jdbc;

  @BeforeEach
  void setup() throws SQLException {
    db = new MigrationTestDatabase();
    jdbc = db.jdbc();
  }

  @AfterEach
  void teardown() throws SQLException {
    db.close();
  }

  @Test
  void createGroupManagerAuthoritiesCreatesOneAuthorityPerGroup() throws Exception {
    jdbc.update("INSERT INTO iam_group (id, uuid, name) VALUES (1, 'g-1', 'production')");

    new V100000_1___CreateGroupManagerAuthorities().migrate(db.context());

    assertThat(jdbc.queryForList("SELECT auth FROM iam_authority", String.class))
      .containsExactly("ROLE_GM:g-1");
  }

  @Test
  void removeOrphanTokensKeepsOnlyValidTokens() throws Exception {
    jdbc.update("INSERT INTO iam_account (id, username) VALUES (1, 'test')");
    jdbc.update("INSERT INTO saved_user_auth (id, name) VALUES (1, 'test'), (2, 'deleted')");
    jdbc.update("INSERT INTO authentication_holder (id) VALUES (1), (2)");
    jdbc.update("INSERT INTO access_token (id, auth_holder_id) VALUES (1, 1), (2, 2), (3, 99)");
    jdbc.update("INSERT INTO refresh_token (id, auth_holder_id) VALUES (1, 1), (2, 2), (3, 99)");

    new V100000_3___RemoveOrphanTokens().migrate(db.context());

    assertThat(jdbc.queryForList("SELECT id FROM access_token", Long.class)).containsExactly(1L);
    assertThat(jdbc.queryForList("SELECT id FROM refresh_token", Long.class)).containsExactly(1L);
  }

  @Test
  void hashClientSecretHashesSecretsWithSha256() throws Exception {
    jdbc.update("INSERT INTO client_details (id, client_secret) "
        + "VALUES (1, 'secret'), (2, NULL)");

    new V1000000_9___HashClientSecret().migrate(db.context());

    assertThat(jdbc.queryForObject("SELECT client_secret FROM client_details WHERE id = 1",
        String.class)).isEqualTo(Sha256Encoder.encode("secret"));
    assertThat(jdbc.queryForObject("SELECT client_secret FROM client_details WHERE id = 2",
        String.class)).isNull();
  }
}
