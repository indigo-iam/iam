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
package it.infn.mw.iam.test.api.scim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType;

class ScimPatchOperationTest {

  private final ObjectMapper mapper = new ObjectMapper();

  @ParameterizedTest
  @CsvSource({"add, add", "Add, add", "ADD, add", "remove, remove", "Remove, remove",
      "REMOVE, remove", "replace, replace", "Replace, replace", "REPLACE, replace"})
  void deserializesOperationTypeCaseInsensitively(String value,
      ScimPatchOperationType expected) throws JsonProcessingException {

    ScimPatchOperationType actual =
        mapper.readValue('"' + value + '"', ScimPatchOperationType.class);

    assertEquals(expected, actual);
  }

  @Test
  void serializesOperationTypeAsLowercase() throws JsonProcessingException {

    assertEquals("\"replace\"", mapper.writeValueAsString(ScimPatchOperationType.replace));
  }

  @Test
  void rejectsUnknownOperationType() {

    assertThrows(JsonProcessingException.class,
        () -> mapper.readValue("\"merge\"", ScimPatchOperationType.class));
  }
}
