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
package db.migration.h2;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import it.infn.mw.iam.persistence.migrations.BaseFlywayJavaMigrationAdapter;
import it.infn.mw.iam.persistence.migrations.CreateGroupManagerAuthorities;

/**
 * 
 * This is included just for consistency among H2 and MySQL. When this migration is executed there
 * will never be groups to migrate. See the test folder for the actual migration
 *
 */
public class V23___CreateGroupManagerAuthorities extends BaseFlywayJavaMigrationAdapter {

  @Override
  public void migrate(JdbcTemplate jdbcTemplate) throws DataAccessException {
    CreateGroupManagerAuthorities task = new CreateGroupManagerAuthorities();
    task.migrate(jdbcTemplate);
  }

}
