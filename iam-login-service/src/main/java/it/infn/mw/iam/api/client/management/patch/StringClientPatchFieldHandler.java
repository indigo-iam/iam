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
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.validation.ConstraintViolation;
import javax.validation.Validator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;

import it.infn.mw.iam.api.client.error.InvalidClientPatchRequestException;
import it.infn.mw.iam.api.client.management.validation.OnClientUpdate;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

public class StringClientPatchFieldHandler implements ClientPatchFieldHandler {

  private static final Set<String> SUPPORTED_OPERATIONS = Set.of("replace");

  private final String path;
  private final String dtoPropertyName;
  private final Function<ClientDetailsEntity, String> getter;
  private final BiConsumer<ClientDetailsEntity, String> setter;
  private final Validator validator;

  public StringClientPatchFieldHandler(String path, String dtoPropertyName,
      Function<ClientDetailsEntity, String> getter, BiConsumer<ClientDetailsEntity, String> setter,
      Validator validator) {
    this.path = path;
    this.dtoPropertyName = dtoPropertyName;
    this.getter = getter;
    this.setter = setter;
    this.validator = validator;
  }

  @Override
  public String getPath() {
    return path;
  }

  @Override
  public Set<String> getSupportedOperations() {
    return SUPPORTED_OPERATIONS;
  }

  @Override
  public JsonNode currentValue(ClientDetailsEntity entity) {
    String value = getter.apply(entity);
    return TextNode.valueOf(value == null ? "" : value);
  }

  @Override
  public Set<ConstraintViolation<RegisteredClientDTO>> validate(JsonNode value) {

    if (!value.isTextual()) {
      throw new InvalidClientPatchRequestException(
          String.format("Patch operation for path '%s' requires a string value", path));
    }

    return validator.validateValue(RegisteredClientDTO.class, dtoPropertyName, value.asText(),
        OnClientUpdate.class);
  }

  @Override
  public void apply(ClientDetailsEntity entity, JsonNode value) {
    setter.accept(entity, value.asText());
  }

}
