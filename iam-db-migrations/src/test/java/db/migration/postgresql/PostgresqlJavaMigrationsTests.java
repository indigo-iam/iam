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
package db.migration.postgresql;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import it.infn.mw.iam.core.Sha256Encoder;
import it.infn.mw.iam.persistence.migrations.MigrationTestDatabase;

class PostgresqlJavaMigrationsTests {

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

  private String stringValue(String sql, Object... args) {
    return jdbc.queryForObject(sql, String.class, args);
  }

  private int count(String sql, Object... args) {
    return jdbc.queryForObject(sql, Integer.class, args);
  }

  @Test
  void passwordUpdateEncodesPasswordsWithBcrypt() throws Exception {
    jdbc.update("INSERT INTO iam_account (id, username, password) VALUES (1, 'test', 'password')");
    jdbc.update("INSERT INTO iam_account (id, username, password) VALUES (2, 'admin', 'secret')");

    new V10_1__Password_Update().migrate(db.context());

    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    assertThat(encoder.matches("password",
        stringValue("SELECT password FROM iam_account WHERE id = 1"))).isTrue();
    assertThat(encoder.matches("secret",
        stringValue("SELECT password FROM iam_account WHERE id = 2"))).isTrue();
  }

  @Test
  void checkDuplicateEmailsMakesDuplicateEmailsUnique() throws Exception {
    jdbc.update("INSERT INTO iam_user_info (id, email) VALUES (10, 'dup@example.org')");
    jdbc.update("INSERT INTO iam_user_info (id, email) VALUES (20, 'dup@example.org')");
    jdbc.update("INSERT INTO iam_user_info (id, email) VALUES (30, 'unique@example.org')");
    jdbc.update("INSERT INTO iam_account (id, uuid, username, user_info_id) "
        + "VALUES (1, 'uuid-1', 'one', 10), (2, 'uuid-2', 'two', 20), (3, 'uuid-3', 'three', 30)");

    new V10_2___CheckDuplicateEmails().migrate(db.context());

    assertThat(stringValue("SELECT email FROM iam_user_info WHERE id = 10"))
      .isEqualTo("1_dup@example.org");
    assertThat(stringValue("SELECT email FROM iam_user_info WHERE id = 20"))
      .isEqualTo("2_dup@example.org");
    assertThat(stringValue("SELECT email FROM iam_user_info WHERE id = 30"))
      .isEqualTo("unique@example.org");
  }

  @Test
  void checkDuplicateEmailsLeavesUniqueEmailsUntouched() throws Exception {
    jdbc.update("INSERT INTO iam_user_info (id, email) VALUES (10, 'one@example.org')");
    jdbc.update("INSERT INTO iam_account (id, uuid, username, user_info_id) "
        + "VALUES (1, 'uuid-1', 'one', 10)");

    new V10_2___CheckDuplicateEmails().migrate(db.context());

    assertThat(stringValue("SELECT email FROM iam_user_info WHERE id = 10"))
      .isEqualTo("one@example.org");
  }

  @Test
  void createGroupManagerAuthoritiesCreatesOneAuthorityPerGroup() throws Exception {
    jdbc.update("INSERT INTO iam_group (id, uuid, name) VALUES (1, 'g-1', 'production')");
    jdbc.update("INSERT INTO iam_group (id, uuid, name) VALUES (2, 'g-2', 'analysis')");

    new V23___CreateGroupManagerAuthorities().migrate(db.context());

    assertThat(jdbc.queryForList("SELECT auth FROM iam_authority ORDER BY auth", String.class))
      .containsExactly("ROLE_GM:g-1", "ROLE_GM:g-2");
  }

  private void insertTokensForOrphanCleanup() {
    jdbc.update("INSERT INTO iam_account (id, username) VALUES (1, 'test')");
    // saved_user_auth 1 belongs to an existing user, 2 to a deleted one
    jdbc.update("INSERT INTO saved_user_auth (id, name) VALUES (1, 'test'), (2, 'deleted')");
    jdbc.update("INSERT INTO authentication_holder (id) VALUES (1), (2)");
    // token 3 points to an authentication holder that does not exist
    jdbc.update("INSERT INTO access_token (id, auth_holder_id) VALUES (1, 1), (2, 2), (3, 99)");
    jdbc.update("INSERT INTO refresh_token (id, auth_holder_id) VALUES (1, 1), (2, 2), (3, 99)");
  }

  private void assertOnlyValidTokensAreLeft() {
    assertThat(jdbc.queryForList("SELECT id FROM access_token", Long.class)).containsExactly(1L);
    assertThat(jdbc.queryForList("SELECT id FROM refresh_token", Long.class)).containsExactly(1L);
  }

  @Test
  void removeOrphanTokensV34RemovesTokensOfDeletedUsersAndInvalidHolders() throws Exception {
    insertTokensForOrphanCleanup();

    new V34_2___RemoveOrphanTokens().migrate(db.context());

    assertOnlyValidTokensAreLeft();
  }

  @Test
  void removeOrphanTokensV81RemovesTokensOfDeletedUsersAndInvalidHolders() throws Exception {
    insertTokensForOrphanCleanup();

    new V81_2___RemoveOrphanTokens().migrate(db.context());

    assertOnlyValidTokensAreLeft();
  }

  @Test
  void extractAccessTokenPayloadConvertsJwtsToClaims() throws Exception {
    String jwt = new PlainJWT(new JWTClaimsSet.Builder().subject("test").issuer("iam").build())
      .serialize();
    String claims = "{\"sub\":\"already-converted\"}";

    jdbc.update("INSERT INTO access_token (id, token_value) VALUES (1, ?)", jwt);
    jdbc.update("INSERT INTO access_token (id, token_value) VALUES (2, ?)", claims);
    jdbc.update("INSERT INTO access_token (id, token_value) VALUES (3, NULL)");

    new V123_2__ExtractAccessTokenPayload().migrate(db.context());

    JWTClaimsSet converted =
        JWTClaimsSet.parse(stringValue("SELECT token_value FROM access_token WHERE id = 1"));
    assertThat(converted.getSubject()).isEqualTo("test");
    assertThat(converted.getIssuer()).isEqualTo("iam");
    assertThat(stringValue("SELECT token_value FROM access_token WHERE id = 2")).isEqualTo(claims);
    assertThat(stringValue("SELECT token_value FROM access_token WHERE id = 3")).isNull();
  }

  @Test
  void extractAccessTokenPayloadProcessesMoreThanOneBatch() throws Exception {
    // The migration reads 1000 rows at a time
    int tokens = 2500;
    List<Object[]> rows = new ArrayList<>();
    for (int i = 1; i <= tokens; i++) {
      rows.add(new Object[] {(long) i,
          new PlainJWT(new JWTClaimsSet.Builder().subject("user-" + i).build()).serialize()});
    }
    jdbc.batchUpdate("INSERT INTO access_token (id, token_value) VALUES (?, ?)", rows);

    new V123_2__ExtractAccessTokenPayload().migrate(db.context());

    assertThat(count("SELECT COUNT(*) FROM access_token WHERE token_value LIKE '{%'"))
      .isEqualTo(tokens);
    assertThat(JWTClaimsSet
      .parse(stringValue("SELECT token_value FROM access_token WHERE id = ?", (long) tokens))
      .getSubject()).isEqualTo("user-" + tokens);
  }

  @Test
  void extractAccessTokenPayloadFailsOnBlankPayload() {
    jdbc.update("INSERT INTO access_token (id, token_value) VALUES (7, '   ')");

    V123_2__ExtractAccessTokenPayload migration = new V123_2__ExtractAccessTokenPayload();

    assertThatThrownBy(() -> migration.migrate(db.context())).isInstanceOf(SQLException.class)
      .hasMessageContaining("Blank access token payload at access_token.id=7");
  }

  @Test
  void extractAccessTokenPayloadFailsOnInvalidPayload() {
    jdbc.update("INSERT INTO access_token (id, token_value) VALUES (8, 'not-a-jwt')");

    V123_2__ExtractAccessTokenPayload migration = new V123_2__ExtractAccessTokenPayload();

    assertThatThrownBy(() -> migration.migrate(db.context())).isInstanceOf(SQLException.class)
      .hasMessageContaining("Invalid access token payload at access_token.id=8");
  }

  @Test
  void extractAccessTokenPayloadFailsOnInvalidJsonPayload() {
    jdbc.update("INSERT INTO access_token (id, token_value) VALUES (9, '{not json')");

    V123_2__ExtractAccessTokenPayload migration = new V123_2__ExtractAccessTokenPayload();

    assertThatThrownBy(() -> migration.migrate(db.context())).isInstanceOf(SQLException.class)
      .hasMessageContaining("Invalid access token payload at access_token.id=9");
  }

  @Test
  void removeDanglingDeviceCodesRemovesApprovedCodesWithoutHolder() throws Exception {
    jdbc.update("INSERT INTO authentication_holder (id) VALUES (1)");
    // 1: approved, valid holder (kept); 2: approved, no holder (removed);
    // 3: approved, deleted holder (removed); 4: not approved yet, no holder (kept)
    jdbc.update("INSERT INTO device_code (id, approved, auth_holder_id) "
        + "VALUES (1, TRUE, 1), (2, TRUE, NULL), (3, TRUE, 42), (4, FALSE, NULL)");
    jdbc.update("INSERT INTO device_code_scope (owner_id, scope) "
        + "VALUES (1, 'openid'), (2, 'openid'), (3, 'openid'), (4, 'openid')");
    jdbc.update("INSERT INTO device_code_request_parameter (owner_id, param) "
        + "VALUES (1, 'p'), (2, 'p'), (3, 'p'), (4, 'p')");

    new V124__RemoveDanglingDeviceCodes().migrate(db.context());

    assertThat(jdbc.queryForList("SELECT id FROM device_code ORDER BY id", Long.class))
      .containsExactly(1L, 4L);
    assertThat(
        jdbc.queryForList("SELECT owner_id FROM device_code_scope ORDER BY owner_id", Long.class))
      .containsExactly(1L, 4L);
    assertThat(jdbc.queryForList(
        "SELECT owner_id FROM device_code_request_parameter ORDER BY owner_id", Long.class))
      .containsExactly(1L, 4L);
  }

  @Test
  void removeDanglingDeviceCodesWithNothingToRemove() throws Exception {
    jdbc.update("INSERT INTO authentication_holder (id) VALUES (1)");
    jdbc.update("INSERT INTO device_code (id, approved, auth_holder_id) VALUES (1, TRUE, 1)");

    new V124__RemoveDanglingDeviceCodes().migrate(db.context());

    assertThat(count("SELECT COUNT(*) FROM device_code")).isEqualTo(1);
  }

  @Test
  void hashClientSecretHashesSecretsWithSha256() throws Exception {
    jdbc.update("INSERT INTO client_details (id, client_secret) "
        + "VALUES (1, 'secret'), (2, NULL)");

    new V125__HashClientSecret().migrate(db.context());

    assertThat(stringValue("SELECT client_secret FROM client_details WHERE id = 1"))
      .isEqualTo(Sha256Encoder.encode("secret"));
    assertThat(stringValue("SELECT client_secret FROM client_details WHERE id = 2")).isNull();
  }
}
