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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.UUID;

import org.flywaydb.core.api.configuration.Configuration;
import org.flywaydb.core.api.migration.Context;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

public class MigrationTestDatabase implements AutoCloseable {

  private static final String[] SCHEMA = {
      "CREATE TABLE iam_user_info (id BIGINT PRIMARY KEY, email VARCHAR(128))",
      "CREATE TABLE iam_account (id BIGINT PRIMARY KEY, uuid VARCHAR(36), username VARCHAR(128),"
          + " password VARCHAR(128), user_info_id BIGINT)",
      "CREATE TABLE iam_group (id BIGINT PRIMARY KEY, uuid VARCHAR(36), name VARCHAR(512))",
      "CREATE TABLE iam_authority (id BIGSERIAL PRIMARY KEY, auth VARCHAR(128) UNIQUE)",
      "CREATE TABLE client_details (id BIGINT PRIMARY KEY, client_secret VARCHAR(2048))",
      "CREATE TABLE authentication_holder (id BIGINT PRIMARY KEY)",
      "CREATE TABLE saved_user_auth (id BIGINT PRIMARY KEY, name VARCHAR(1024))",
      "CREATE TABLE access_token (id BIGINT PRIMARY KEY, token_value TEXT,"
          + " auth_holder_id BIGINT)",
      "CREATE TABLE refresh_token (id BIGINT PRIMARY KEY, auth_holder_id BIGINT)",
      "CREATE TABLE device_code (id BIGINT PRIMARY KEY, approved BOOLEAN,"
          + " auth_holder_id BIGINT)",
      "CREATE TABLE device_code_scope (owner_id BIGINT, scope VARCHAR(256))",
      "CREATE TABLE device_code_request_parameter (owner_id BIGINT, param VARCHAR(2048))"};

  private final Connection connection;
  private final JdbcTemplate jdbcTemplate;

  public MigrationTestDatabase() throws SQLException {
    connection = DriverManager.getConnection(String.format(
        "jdbc:h2:mem:%s;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH",
        UUID.randomUUID()));
    jdbcTemplate = new JdbcTemplate(new SingleConnectionDataSource(connection, true));
    jdbcTemplate.batchUpdate(SCHEMA);
  }

  public JdbcTemplate jdbc() {
    return jdbcTemplate;
  }

  public Context context() {
    return new Context() {

      @Override
      public Configuration getConfiguration() {
        return null;
      }

      @Override
      public Connection getConnection() {
        return connection;
      }
    };
  }

  @Override
  public void close() throws SQLException {
    connection.close();
  }
}
