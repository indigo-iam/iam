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
package it.infn.mw.iam.test.db_upgrade;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.BindMode;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import it.infn.mw.iam.test.util.db.MySQL57TestContainer;

@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles({"mysql-test", "flyway-repair"})
@DirtiesContext
public class Upgradev1_7_2Db57Tests extends UpgradeDbTestSupport {

  public static final String DB_DUMP = "iam-v1.7.2-mysql5.7.sql";

  @Container
  static MySQL57TestContainer db =
      new MySQL57TestContainer().withClasspathResourceMapping(
          joinPathStrings(DB_DUMPS_DIR, DB_DUMP), joinPathStrings(INITDB_DIR, DB_DUMP),
          BindMode.READ_ONLY);

  @DynamicPropertySource
  static void registerMysqlConnectionString(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", db::getJdbcUrl);
  }

  @Test
  public void dbUpgradeSucceeds() throws IOException {
    assertThat(accountService.count("Admin User"), equalTo(1L));
  }

}
