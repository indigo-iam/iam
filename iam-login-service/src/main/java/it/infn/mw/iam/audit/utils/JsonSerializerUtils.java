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
package it.infn.mw.iam.audit.utils;

import java.io.IOException;
import java.util.Collection;

import com.fasterxml.jackson.core.JsonGenerator;

public class JsonSerializerUtils {

  private JsonSerializerUtils() {
    // prevent instantiation
  }

  public static <T extends Number> void nullSafeWriteNumberField(JsonGenerator gen, String key,
      T value) throws IOException {
    if (value != null) {
      gen.writeNumberField(key, value.longValue());
    } else {
      gen.writeNullField(key);
    }
  }

  public static void serializeStringArray(JsonGenerator gen, String key,
      Collection<String> values) throws IOException {
    if (values != null) {
      gen.writeArrayFieldStart(key);
      for (String s : values) {
        gen.writeString(s);
      }
    }
    gen.writeEndArray();
  }

}
