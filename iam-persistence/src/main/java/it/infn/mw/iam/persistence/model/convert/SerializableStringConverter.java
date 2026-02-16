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
package it.infn.mw.iam.persistence.model.convert;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Converter
public class SerializableStringConverter implements AttributeConverter<Serializable, String> {

  private static Logger logger = LoggerFactory.getLogger(SerializableStringConverter.class);

  @Override
  public String convertToDatabaseColumn(Serializable attribute) {

    if (attribute == null) {
      return null;
    }
    if (attribute instanceof String) {
      return (String) attribute;
    }
    if (attribute instanceof Long) {
      return attribute.toString();
    }
    if (attribute instanceof Date) {
      return Long.toString(((Date) attribute).getTime());
    } 
    logger.warn("Dropping data from request: " + attribute + " :: " + attribute.getClass());
    return null;
  }

  @Override
  public Serializable convertToEntityAttribute(String dbData) {
    return dbData;
  }

}
