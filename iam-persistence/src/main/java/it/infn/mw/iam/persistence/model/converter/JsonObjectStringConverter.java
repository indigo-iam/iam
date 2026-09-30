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

import java.text.ParseException;
import java.util.Map;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import com.nimbusds.jose.util.JSONObjectUtils;

@Converter
public class JsonObjectStringConverter implements AttributeConverter<Map<String, Object>, String> {

  @Override
  public String convertToDatabaseColumn(Map<String, Object> value) {
    return value == null ? null : JSONObjectUtils.toJSONString(value);
  }

  @Override
  public Map<String, Object> convertToEntityAttribute(String value) {
    if (value == null) {
      return null;
    }
    try {
      Map<String, Object> result = JSONObjectUtils.parse(value);
      if (result == null) {
        throw new IllegalArgumentException("Invalid stored access token JSON payload");
      }
      return result;
    } catch (ParseException e) {
      throw new IllegalArgumentException("Invalid stored access token JSON payload");
    }
  }
}
