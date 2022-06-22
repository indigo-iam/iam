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
package it.infn.mw.iam.test.util.db;

import org.testcontainers.containers.MySQLContainer;

public class MySQL80TestContainer extends MySQLContainer<MySQL80TestContainer> {

  public static final String DEFAULT_IMAGE = "mysql:8.0";
  public static final String DEFAULT_DATABASE_NAME = "iam";
  public static final String DEFAULT_USERNAME = "iam";
  public static final String DEFAULT_PASSWORD = "pwd";

  public MySQL80TestContainer() {
    super(DEFAULT_IMAGE);
    withDatabaseName(DEFAULT_DATABASE_NAME);
    withPassword(DEFAULT_PASSWORD);
    withUsername(DEFAULT_USERNAME);
  }

}
