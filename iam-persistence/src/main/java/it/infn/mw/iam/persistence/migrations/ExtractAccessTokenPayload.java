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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTParser;

/**
 * Converts JWT values to JSON claims using bounded, primary-key ordered batches.
 */
public final class ExtractAccessTokenPayload {

  private static final int BATCH_SIZE = 1000;

  private static final String SELECT_BATCH =
      "SELECT id, token_value FROM access_token WHERE id > ? ORDER BY id LIMIT ?";

  private static final String UPDATE_PAYLOAD =
      "UPDATE access_token SET token_value = ? WHERE id = ?";

  private record Row(long id, String value) {
  }

  private ExtractAccessTokenPayload() {}

  public static void migrate(Connection connection) throws SQLException {
    try (PreparedStatement select = connection.prepareStatement(SELECT_BATCH);
        PreparedStatement update = connection.prepareStatement(UPDATE_PAYLOAD)) {

      select.setInt(2, BATCH_SIZE);

      List<Row> rows = readBatch(select, Long.MIN_VALUE);

      while (!rows.isEmpty()) {
        updateBatch(update, rows);
        long lastId = rows.get(rows.size() - 1).id();
        rows = readBatch(select, lastId);
      }
    }
  }

  private static List<Row> readBatch(PreparedStatement select, long lastId) throws SQLException {

    select.setLong(1, lastId);

    List<Row> rows = new ArrayList<>(BATCH_SIZE);
    try (ResultSet result = select.executeQuery()) {
      while (result.next()) {
        rows.add(new Row(result.getLong(1), result.getString(2)));
      }
    }
    return rows;
  }

  private static void updateBatch(PreparedStatement update, List<Row> rows) throws SQLException {

    int pending = 0;

    for (Row row : rows) {
      String payload = payloadToUpdate(row);
      if (payload != null) {
        update.setString(1, payload);
        update.setLong(2, row.id());
        update.addBatch();
        pending++;
      }
    }

    if (pending > 0) {
      update.executeBatch();
      update.clearBatch();
    }
  }

  private static String payloadToUpdate(Row row) throws SQLException {
    String value = row.value();
    if (value == null || value.isBlank()) {
      return null;
    }

    String trimmed = value.trim();

    // Check if the token value has been already migrated to JSON format
    if (trimmed.startsWith("{")) {
      try {
        JSONObjectUtils.parse(trimmed);
        return trimmed;
      } catch (Exception e) {
        throw new SQLException("Malformed JSON payload at access_token.id=" + row.id(), e);
      }
    }

    // Not JSON; attempt to parse as JWT and extract claims
    try {
      return JSONObjectUtils
        .toJSONString(JWTParser.parse(trimmed).getJWTClaimsSet().toJSONObject());
    } catch (ParseException e) {
      throw new SQLException("Invalid access token payload at access_token.id=" + row.id(), e);
    }
  }
}
