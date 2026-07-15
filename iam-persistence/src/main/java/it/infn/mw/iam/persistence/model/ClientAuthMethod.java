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
package it.infn.mw.iam.persistence.model;

import java.util.HashMap;
import java.util.Map;

public enum ClientAuthMethod {
  SECRET_POST("client_secret_post"), SECRET_BASIC("client_secret_basic"), SECRET_JWT(
      "client_secret_jwt"), PRIVATE_KEY("private_key_jwt"), NONE("none");

  private final String value;

  private static final Map<String, ClientAuthMethod> lookup = new HashMap<>();
  static {
    for (ClientAuthMethod a : ClientAuthMethod.values()) {
      lookup.put(a.getValue(), a);
    }
  }

  ClientAuthMethod(String value) {
    this.value = value;
  }

  public String getValue() {
    return value;
  }

  public static ClientAuthMethod getByValue(String value) {
    return lookup.get(value);
  }
}