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

public enum SubjectType {

  PAIRWISE("pairwise"),
  PUBLIC("public");

  private final String value;

  private static final Map<String, SubjectType> lookup = new HashMap<>();
  static {
    for (SubjectType u : SubjectType.values()) {
      lookup.put(u.getValue(), u);
    }
  }

  SubjectType(String value) {
    this.value = value;
  }

  public String getValue() {
    return value;
  }

  public static SubjectType getByValue(String value) {
    return lookup.get(value);
  }
}
