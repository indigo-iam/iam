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
package it.infn.mw.iam.api.common.client;

import java.io.IOException;
import java.util.Collection;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class CollectionAsStringSerializer extends JsonSerializer<Collection<String>> {

  @Override
  public void serialize(Collection<String> value, JsonGenerator gen, SerializerProvider serializers)
      throws IOException {

    if (value == null || value.isEmpty()) {
      gen.writeNull();
    } else {
      gen.writeString(value.stream()
        .map(String::trim)
        .filter(s -> !s.isBlank())
        .collect(Collectors.joining(" ")));
    }

  }

}
