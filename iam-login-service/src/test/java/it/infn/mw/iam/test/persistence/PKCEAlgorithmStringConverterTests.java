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
package it.infn.mw.iam.test.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mitre.oauth2.model.PKCEAlgorithm;
import org.mitre.oauth2.model.convert.PKCEAlgorithmStringConverter;

class PKCEAlgorithmStringConverterTests {

  private PKCEAlgorithmStringConverter converter = new PKCEAlgorithmStringConverter();

  @Test
  void shouldConvertAlgorithmToDatabaseColumn() {
    assertThat(converter.convertToDatabaseColumn(PKCEAlgorithm.S256)).isEqualTo("S256");
  }

  @Test
  void shouldConvertNullAlgorithmToNullDatabaseColumn() {
    assertThat(converter.convertToDatabaseColumn(null)).isNull();
  }

  @Test
  void shouldConvertDatabaseValueToAlgorithm() {
    assertThat(converter.convertToEntityAttribute("S256")).isEqualTo(PKCEAlgorithm.S256);
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "   ", "\t", "\n"})
  void shouldUseOptionalForMissingDatabaseValue(String dbData) {
    assertThat(converter.convertToEntityAttribute(dbData)).isEqualTo(PKCEAlgorithm.optional);
  }

  @Test
  void shouldRejectUnknownDatabaseValue() {
    assertThatThrownBy(() -> converter.convertToEntityAttribute("unknown"))
      .isInstanceOf(IllegalArgumentException.class);
  }
}