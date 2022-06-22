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
package it.infn.mw.iam.test.util.redis;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

public class RedisContainer extends GenericContainer<RedisContainer> {
  public static final String DEFAULT_REDIS_IMAGE = "redis:6-alpine";
  public static final int DEFAULT_REDIS_PORT = 6379;

  public RedisContainer(String dockerImageName) {
    super(DockerImageName.parse(dockerImageName));
    withExposedPorts(DEFAULT_REDIS_PORT);
  }

  public RedisContainer() {
    super(DEFAULT_REDIS_IMAGE);
    withExposedPorts(DEFAULT_REDIS_PORT);
  }

}
