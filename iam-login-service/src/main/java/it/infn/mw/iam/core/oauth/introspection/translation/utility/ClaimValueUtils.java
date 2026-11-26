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
package it.infn.mw.iam.core.oauth.introspection.translation.utility;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import it.infn.mw.iam.core.oauth.introspection.translation.TranslationException;

public final class ClaimValueUtils {

  private ClaimValueUtils() {}

  public static List<String> readValues(String claimName, Object value) {
    if (value == null) {
      throw new TranslationException("Null value found for claim: " + claimName);
    }

    if ("scope".equals(claimName)) {
      if (!(value instanceof String scope)) {
        throw new TranslationException("The scope claim must be a String");
      }

      if (scope.isBlank()) {
        return new ArrayList<>();
      }

      return new ArrayList<>(Arrays.asList(scope.trim().split("\\s+")));
    }

    if (value instanceof String stringValue) {
      return new ArrayList<>(List.of(stringValue));
    }

    if (value instanceof Collection<?> collection) {
      List<String> values = new ArrayList<>();

      for (Object item : collection) {
        if (!(item instanceof String stringItem)) {
          throw new TranslationException("Claim values must be Strings: " + claimName);
        }
        values.add(stringItem);
      }

      return values;
    }

    throw new TranslationException("Unsupported value type for claim: " + claimName);
  }

  public static Object writeValues(String claimName, List<String> values,
      boolean originallyCollection) {

    if ("scope".equals(claimName)) {
      return String.join(" ", values);
    }

    if (originallyCollection) {
      return new ArrayList<>(values);
    }

    if (values.size() == 1) {
      return values.get(0);
    }

    return new ArrayList<>(values);
  }
}
