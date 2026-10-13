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

import java.util.Set;

import javax.validation.ConstraintViolation;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

public interface ClientPatchFieldHandler {

  String getPath();

  Set<String> getSupportedOperations();

  JsonNode currentValue(ClientDetailsEntity entity);

  /**
   * Validates a patched value without side effects.
   *
   * @return the Bean Validation violations for the value, empty if valid
   * @throws it.infn.mw.iam.api.client.error.InvalidClientPatchRequestException if the value has
   *         the wrong JSON type for this field
   */
  Set<? extends ConstraintViolation<?>> validate(JsonNode value);

  /** Writes a value that has already passed {@link #validate(JsonNode)} onto the entity. */
  void apply(ClientDetailsEntity entity, JsonNode value);

}
