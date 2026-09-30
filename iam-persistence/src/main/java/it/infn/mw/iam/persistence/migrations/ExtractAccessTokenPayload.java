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

/** Converts JWT values to JSON claims using bounded, primary-key ordered batches. */
public final class ExtractAccessTokenPayload {

  private static final int BATCH_SIZE = 1000;

  private record Row(long id, String value) {
  }

  private ExtractAccessTokenPayload() {}

  public static void migrate(Connection connection) throws SQLException {

    long lastId = Long.MIN_VALUE;
    try (
        PreparedStatement select = connection.prepareStatement(
            "SELECT id, token_value FROM access_token WHERE id > ? ORDER BY id LIMIT ?");
        PreparedStatement update =
            connection.prepareStatement("UPDATE access_token SET token_value = ? WHERE id = ?")) {
      while (true) {
        select.setLong(1, lastId);
        select.setInt(2, BATCH_SIZE);
        List<Row> rows = new ArrayList<>(BATCH_SIZE);
        try (ResultSet result = select.executeQuery()) {
          while (result.next()) {
            rows.add(new Row(result.getLong(1), result.getString(2)));
          }
        }
        if (rows.isEmpty()) {
          return;
        }
        int pending = 0;
        for (Row row : rows) {
          String value = row.value();
          if (value != null) {
            try {
              if (value.stripLeading().startsWith("{")) {
                // Allow a retry after a partially completed non-transactional run.
                if (JSONObjectUtils.parse(value) == null) {
                  throw new ParseException("Invalid JSON object", 0);
                }
              } else {
                String payload = JSONObjectUtils
                  .toJSONString(JWTParser.parse(value).getJWTClaimsSet().toJSONObject());
                update.setString(1, payload);
                update.setLong(2, row.id());
                update.addBatch();
                pending++;
              }
            } catch (ParseException e) {
              // Never include the token, claims, or parser exception in the error.
              throw new SQLException("Invalid access token payload at access_token.id=" + row.id());
            }
          }
        }
        if (pending > 0) {
          update.executeBatch();
          update.clearBatch();
        }
        lastId = rows.get(rows.size() - 1).id();
      }
    }
  }
}
