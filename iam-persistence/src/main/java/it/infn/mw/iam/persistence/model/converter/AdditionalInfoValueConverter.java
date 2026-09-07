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
package it.infn.mw.iam.persistence.model.converter;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@Converter
public class AdditionalInfoValueConverter implements AttributeConverter<Object, String> {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  @Override
  public String convertToDatabaseColumn(Object value) {
    if (value == null) {
      return null;
    }

    try {
      return OBJECT_MAPPER.writeValueAsString(value);
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException("Unable to serialize additional info value", e);
    }
  }

  @Override
  public Object convertToEntityAttribute(String value) {
    if (value == null) {
      return null;
    }

    try {
      return OBJECT_MAPPER.readValue(value, Object.class);
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException("Unable to deserialize additional info value", e);
    }
  }
}
