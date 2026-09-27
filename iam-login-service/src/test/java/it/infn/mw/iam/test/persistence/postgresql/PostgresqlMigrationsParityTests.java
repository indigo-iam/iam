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
package it.infn.mw.iam.test.persistence.postgresql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

/**
 * Checks that every MySQL migration has a PostgreSQL counterpart with the same version and of
 * the same kind (SQL or Java), so that the two schemas do not diverge.
 */
class PostgresqlMigrationsParityTests {

  private static final Pattern MIGRATION_NAME = Pattern.compile("^V([0-9_]+?)_*__.*\\.(sql|class)$");

  private Map<String, String> migrations(String location) throws IOException {

    Map<String, String> versions = new TreeMap<>();
    Resource[] resources = new PathMatchingResourcePatternResolver()
      .getResources(String.format("classpath*:db/migration/%s/V*", location));

    for (Resource r : resources) {
      Matcher m = MIGRATION_NAME.matcher(r.getFilename());
      if (m.matches()) {
        versions.put(m.group(1), m.group(2));
      }
    }
    return versions;
  }

  @Test
  void postgresqlMigrationsMatchMysqlOnes() throws IOException {

    Map<String, String> mysql = migrations("mysql");
    Map<String, String> postgresql = migrations("postgresql");

    assertFalse(mysql.isEmpty());
    assertEquals(mysql, postgresql);
  }
}
