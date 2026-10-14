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

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.rowset.SqlRowSet;

import it.infn.mw.iam.persistence.migrations.BaseFlywayJavaMigrationAdapter;

public class V10_2___CheckDuplicateEmails extends BaseFlywayJavaMigrationAdapter {

  public static final Logger LOG = LoggerFactory.getLogger(V10_2___CheckDuplicateEmails.class);

  @Override
  public void migrate(JdbcTemplate jdbcTemplate) throws DataAccessException {

    SqlRowSet rowSet = jdbcTemplate
      .queryForRowSet("SELECT email from iam_user_info group by email having count(email) > 1");

    List<String> duplicateEmails = new ArrayList<>();

    while (rowSet.next()) {
      String email = rowSet.getString("email");
      duplicateEmails.add(email);
    }

    // Disable users with duplicate email
    if (!duplicateEmails.isEmpty()) {
      LOG.debug("### DUPLICATE EMAIL WARNING ###");
      LOG.debug("Found multiple accounts linked to the same email. "
          + "This upgrade script will change the email address for users");

      for (String email : duplicateEmails) {
        rowSet =
            jdbcTemplate.queryForRowSet(
                "SELECT iam_account.id, iam_account.uuid from iam_account, iam_user_info where "
                    + "iam_account.user_info_id = iam_user_info.id and iam_user_info.email = ?",
                email);

        while (rowSet.next()) {

          Integer accountId = rowSet.getInt("id");
          String accountUuid = rowSet.getString("uuid");

          String uniqueUpdatedEmail = String.format("%d_%s", accountId, email);

          int updateResult = jdbcTemplate.update(
              "update iam_user_info set iam_user_info.email = ? "
                  + "where id = (select user_info_id from iam_account where iam_account.id = ?)",
              uniqueUpdatedEmail, accountId);

          if (updateResult == 1) {
            LOG.warn("Updated email for IAM account {} (uuid: {}). New email: {}", accountId,
                accountUuid, uniqueUpdatedEmail);
          }
        }

      }
      LOG.debug("### END Of DUPLICATE EMAIL WARNING ###");
    }
  }

}
