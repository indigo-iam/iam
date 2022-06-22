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

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class RedisIamTestExtension
    implements BeforeAllCallback, AfterAllCallback, BeforeEachCallback, AfterEachCallback {

  private final RedisContainer redis = new RedisContainer();

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    redis.stop();
  }

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    redis.start();
    System.setProperty("spring.redis.port", String.valueOf(redis.getFirstMappedPort()));
    System.setProperty("spring.session.store-type", "redis");
  }

  @Override
  public void beforeAll(ExtensionContext context) throws Exception {
    redis.start();
    System.setProperty("spring.redis.port", String.valueOf(redis.getFirstMappedPort()));
    System.setProperty("spring.session.store-type", "redis");

  }

  @Override
  public void afterAll(ExtensionContext context) throws Exception {
    redis.stop();
  }

}
