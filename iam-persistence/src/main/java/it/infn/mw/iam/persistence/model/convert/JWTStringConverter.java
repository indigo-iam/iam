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

import java.text.ParseException;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

@Converter
public class JWTStringConverter implements AttributeConverter<JWT, String> {

  public static Logger logger = LoggerFactory.getLogger(JWTStringConverter.class);

  @Override
  public String convertToDatabaseColumn(JWT attribute) {
    if (attribute != null) {
      return attribute.serialize();
    } else {
      return null;
    }
  }

  @Override
  public JWT convertToEntityAttribute(String dbData) {
    if (dbData != null) {
      try {
        JWT jwt = JWTParser.parse(dbData);
        return jwt;
      } catch (ParseException e) {
        logger.error("Unable to parse JWT", e);
        return null;
      }
    } else {
      return null;
    }
  }

}
