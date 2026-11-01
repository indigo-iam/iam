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

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import com.nimbusds.jwt.JWTClaimsSet;

@Converter
public class JWTClaimsSetStringConverter implements AttributeConverter<JWTClaimsSet, String> {

  @Override
  public String convertToDatabaseColumn(JWTClaimsSet claims) {
    return claims == null ? null : claims.toString();
  }

  @Override
  public JWTClaimsSet convertToEntityAttribute(String value) {
    if (value == null) {
      return null;
    }
    try {
      return JWTClaimsSet.parse(value);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Invalid stored access token claims");
    }
  }
}
