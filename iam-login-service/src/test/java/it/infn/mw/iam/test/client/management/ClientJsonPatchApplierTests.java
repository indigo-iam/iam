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
package it.infn.mw.iam.test.client.management;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import javax.validation.ConstraintViolationException;
import javax.validation.Validation;
import javax.validation.Validator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.client.error.InvalidClientPatchRequestException;
import it.infn.mw.iam.api.client.management.patch.ClientJsonPatchApplier;
import it.infn.mw.iam.api.client.management.patch.ClientPatchHandlerRegistry;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

class ClientJsonPatchApplierTests {

  final ObjectMapper mapper = new ObjectMapper();
  final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
  final ClientJsonPatchApplier applier =
      new ClientJsonPatchApplier(new ClientPatchHandlerRegistry(validator));

  private ClientDetailsEntity clientWith(String name, String description) {
    ClientDetailsEntity entity = new ClientDetailsEntity();
    entity.setClientName(name);
    entity.setClientDescription(description);
    return entity;
  }

  @Test
  void replacesClientName() throws Exception {
    JsonNode patch = mapper
      .readTree("[{\"op\":\"replace\",\"path\":\"/client_name\",\"value\":\"new-name\"}]");
    ClientDetailsEntity entity = clientWith("current-name", "current description");

    ClientDetailsEntity patched = applier.apply(entity, patch);

    assertEquals("new-name", patched.getClientName());
    assertEquals("current description", patched.getClientDescription());
  }

  @Test
  void replacesClientDescriptionAndEmptyBecomesNull() throws Exception {
    JsonNode patch =
        mapper.readTree("[{\"op\":\"replace\",\"path\":\"/client_description\",\"value\":\"\"}]");
    ClientDetailsEntity entity = clientWith("current-name", "current description");

    ClientDetailsEntity patched = applier.apply(entity, patch);

    assertEquals("current-name", patched.getClientName());
    assertNull(patched.getClientDescription());
  }

  @Test
  void replacesBothFieldsInOneRequest() throws Exception {
    JsonNode patch = mapper.readTree(
        "[{\"op\":\"replace\",\"path\":\"/client_name\",\"value\":\"new-name\"},"
            + "{\"op\":\"replace\",\"path\":\"/client_description\",\"value\":\"new description\"}]");
    ClientDetailsEntity entity = clientWith("current-name", "current description");

    ClientDetailsEntity patched = applier.apply(entity, patch);

    assertEquals("new-name", patched.getClientName());
    assertEquals("new description", patched.getClientDescription());
  }

  static Stream<Arguments> invalidPatchRequests() {
    return Stream.of(
        Arguments.of("[]", "non-empty"),
        Arguments.of("{\"op\":\"replace\",\"path\":\"/client_name\",\"value\":\"x\"}", "non-empty"),
        Arguments.of("[{\"op\":\"add\",\"path\":\"/client_name\",\"value\":\"x\"}]",
            "Unsupported patch operation"),
        Arguments.of("[{\"op\":\"replace\",\"path\":\"/client_id\",\"value\":\"x\"}]",
            "Unsupported patch path"),
        Arguments.of("[{\"op\":\"replace\",\"path\":\"/client_name\",\"value\":42}]",
            "requires a string value"));
  }

  @ParameterizedTest
  @MethodSource("invalidPatchRequests")
  void rejectsInvalidPatchRequests(String patchJson, String expectedMessageFragment)
      throws Exception {
    JsonNode patch = mapper.readTree(patchJson);
    ClientDetailsEntity entity = clientWith("name", "desc");

    InvalidClientPatchRequestException e =
        assertThrows(InvalidClientPatchRequestException.class, () -> applier.apply(entity, patch));

    assertTrue(e.getMessage().contains(expectedMessageFragment));
  }

  @Test
  void rejectsValueFailingBeanValidation() throws Exception {
    String tooLongName = "n".repeat(300);
    JsonNode patch = mapper.readTree(
        String.format("[{\"op\":\"replace\",\"path\":\"/client_name\",\"value\":\"%s\"}]",
            tooLongName));
    ClientDetailsEntity entity = clientWith("name", "desc");

    assertThrows(ConstraintViolationException.class, () -> applier.apply(entity, patch));
  }

  @Test
  void leavesEntityUntouchedWhenAnyOperationFailsValidation() throws Exception {
    JsonNode patch = mapper.readTree(String.format(
        "[{\"op\":\"replace\",\"path\":\"/client_name\",\"value\":\"valid-new-name\"},"
            + "{\"op\":\"replace\",\"path\":\"/client_description\",\"value\":\"%s\"}]",
        "d".repeat(2000)));
    ClientDetailsEntity entity = clientWith("current-name", "current description");

    assertThrows(ConstraintViolationException.class, () -> applier.apply(entity, patch));

    assertEquals("current-name", entity.getClientName());
    assertEquals("current description", entity.getClientDescription());
  }

  @Test
  void reportsAllViolationsAtOnce() throws Exception {
    JsonNode patch = mapper.readTree(String.format(
        "[{\"op\":\"replace\",\"path\":\"/client_name\",\"value\":\"%s\"},"
            + "{\"op\":\"replace\",\"path\":\"/client_description\",\"value\":\"%s\"}]",
        "n".repeat(300), "d".repeat(2000)));
    ClientDetailsEntity entity = clientWith("name", "desc");

    ConstraintViolationException e =
        assertThrows(ConstraintViolationException.class, () -> applier.apply(entity, patch));

    assertEquals(2, e.getConstraintViolations().size());
  }

  @Test
  void rejectsReplaceWithoutValue() throws Exception {
    JsonNode patch = mapper.readTree("[{\"op\":\"replace\",\"path\":\"/client_name\"}]");
    ClientDetailsEntity entity = clientWith("name", "desc");

    InvalidClientPatchRequestException e =
        assertThrows(InvalidClientPatchRequestException.class, () -> applier.apply(entity, patch));

    assertEquals("Patch operation 'replace' for path '/client_name' requires a 'value' member",
        e.getMessage());
  }

  @Test
  void rejectsNonObjectOperation() throws Exception {
    JsonNode patch = mapper.readTree("[\"replace\"]");
    ClientDetailsEntity entity = clientWith("name", "desc");

    InvalidClientPatchRequestException e =
        assertThrows(InvalidClientPatchRequestException.class, () -> applier.apply(entity, patch));

    assertTrue(e.getMessage().contains("must be a JSON object"));
  }
}
