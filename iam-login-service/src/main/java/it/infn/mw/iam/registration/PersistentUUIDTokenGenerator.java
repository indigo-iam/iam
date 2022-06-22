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
package it.infn.mw.iam.registration;

import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

@Component
@Primary
public class PersistentUUIDTokenGenerator implements TokenGenerator {

  private String lastToken;

  private UUIDTokenGenerator generator;

  public PersistentUUIDTokenGenerator() {
    generator = new UUIDTokenGenerator();
  }

  @Override
  public String generateToken() {
    lastToken = generator.generateToken();
    return lastToken;
  }

  public String getLastToken() {
    return lastToken;
  }

}
