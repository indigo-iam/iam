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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.SpringApplication;
import org.testcontainers.containers.BindMode;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.db.MySQL57TestContainer;
import it.infn.mw.iam.test.util.db.MySQL80TestContainer;

@Testcontainers(disabledWithoutDocker = true)
@Disabled("MySQL 5.7 no more supported")
public class Upgradev1_7_0DbTests extends UpgradeDbTestSupport {

  public static final String DB_DUMP = "iam-v1.7.0-mysql5.7.sql";

  @Container
  static MySQL57TestContainer db57 =
      new MySQL57TestContainer().withClasspathResourceMapping(
          joinPathStrings(DB_DUMPS_DIR, DB_DUMP), joinPathStrings(INITDB_DIR, DB_DUMP),
          BindMode.READ_ONLY);

  @Container
  static MySQL80TestContainer db80 =
      new MySQL80TestContainer().withClasspathResourceMapping(
          joinPathStrings(DB_DUMPS_DIR, DB_DUMP), joinPathStrings(INITDB_DIR, DB_DUMP),
          BindMode.READ_ONLY);

  @Test
  public void dbUpgradeFailsGracefully() throws Exception {
    
    SpringApplication iamApp = new SpringApplication(IamLoginService.class);

    BeanCreationException exception = assertThrows(BeanCreationException.class, () -> {
      iamApp.run("--spring.profiles.active=mysql-test,flyway-repair",
          "--spring.datasource.url=" + db57.getJdbcUrl());
    });

    assertThat(exception.getMessage(),
        containsString("'version_rank' doesn't have a default value"));
  }

  @Test
  public void db80UpgradeFailsGracefully() throws Exception {

    SpringApplication iamApp = new SpringApplication(IamLoginService.class);

    BeanCreationException exception = assertThrows(BeanCreationException.class, () -> {
      iamApp.run("--spring.profiles.active=mysql-test,flyway-repair",
          "--spring.datasource.url=" + db80.getJdbcUrl());
    });

    assertThat(exception.getMessage(),
        containsString("'version_rank' doesn't have a default value"));
  }

}
