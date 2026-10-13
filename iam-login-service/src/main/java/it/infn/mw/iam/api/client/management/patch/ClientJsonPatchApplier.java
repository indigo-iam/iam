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
package it.infn.mw.iam.api.client.management.patch;

import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.fge.jsonpatch.JsonPatch;
import com.github.fge.jsonpatch.JsonPatchException;

import it.infn.mw.iam.api.client.error.InvalidClientPatchRequestException;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

@Component
public class ClientJsonPatchApplier {

  private static final Set<String> OPERATIONS_REQUIRING_VALUE = Set.of("replace");

  private final ClientPatchHandlerRegistry registry;

  public ClientJsonPatchApplier(ClientPatchHandlerRegistry registry) {
    this.registry = registry;
  }

  public ClientDetailsEntity apply(ClientDetailsEntity entity, JsonNode patchRequest) {

    if (!patchRequest.isArray() || patchRequest.isEmpty()) {
      throw new InvalidClientPatchRequestException(
          "Patch request must be a non-empty JSON array of operations");
    }

    for (JsonNode operation : patchRequest) {
      validateOperation(operation);
    }

    ObjectNode currentFields = JsonNodeFactory.instance.objectNode();
    for (String path : registry.supportedPaths()) {
      ClientPatchFieldHandler handler = registry.get(path).orElseThrow();
      currentFields.set(fieldName(path), handler.currentValue(entity));
    }

    JsonNode patchedFields;
    try {
      patchedFields = JsonPatch.fromJson(patchRequest).apply(currentFields);
    } catch (JsonPatchException | IOException e) {
      throw new InvalidClientPatchRequestException("Invalid patch request: " + e.getMessage());
    }

    Set<String> touchedPaths = new LinkedHashSet<>();
    patchRequest.forEach(operation -> touchedPaths.add(operation.path("path").asText()));

    Set<ConstraintViolation<?>> violations = new HashSet<>();
    for (String path : touchedPaths) {
      violations
        .addAll(registry.get(path).orElseThrow().validate(patchedFields.path(fieldName(path))));
    }
    if (!violations.isEmpty()) {
      throw new ConstraintViolationException(violations);
    }

    for (String path : touchedPaths) {
      registry.get(path).orElseThrow().apply(entity, patchedFields.path(fieldName(path)));
    }

    return entity;
  }

  private void validateOperation(JsonNode operation) {

    if (!operation.isObject()) {
      throw new InvalidClientPatchRequestException("Each patch operation must be a JSON object");
    }

    String op = operation.path("op").asText(null);
    String path = operation.path("path").asText(null);

    ClientPatchFieldHandler handler = registry.get(path)
      .orElseThrow(() -> new InvalidClientPatchRequestException(String.format(
          "Unsupported patch path '%s': supported paths are %s", path, registry.supportedPaths())));

    if (!handler.getSupportedOperations().contains(op)) {
      throw new InvalidClientPatchRequestException(
          String.format("Unsupported patch operation '%s' for path '%s': supported operations are %s",
              op, path, handler.getSupportedOperations()));
    }

    if (OPERATIONS_REQUIRING_VALUE.contains(op) && !operation.has("value")) {
      throw new InvalidClientPatchRequestException(
          String.format("Patch operation '%s' for path '%s' requires a 'value' member", op, path));
    }
  }

  private static String fieldName(String jsonPointerPath) {
    return jsonPointerPath.substring(1);
  }

}
