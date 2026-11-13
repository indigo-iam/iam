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

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.validation.Validator;

import org.springframework.stereotype.Component;

import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

/**
 * Registry of the fields a client resource currently exposes to PATCH, keyed by RFC 6902 JSON
 * pointer path.
 *
 * To make a new field patchable, add a handler here: no change is needed in
 * {@link ClientJsonPatchApplier}, which only talks to this registry.
 */
@Component
public class ClientPatchHandlerRegistry {

  private final Map<String, ClientPatchFieldHandler> handlersByPath;

  public ClientPatchHandlerRegistry(Validator validator) {

    List<ClientPatchFieldHandler> handlers = List.of(
        new StringClientPatchFieldHandler("/client_name", "clientName",
            ClientDetailsEntity::getClientName, ClientDetailsEntity::setClientName, validator),
        new StringClientPatchFieldHandler("/client_description", "clientDescription",
            ClientDetailsEntity::getClientDescription,
            (entity, value) -> entity.setClientDescription(value.isEmpty() ? null : value),
            validator));

    this.handlersByPath =
        handlers.stream().collect(Collectors.toMap(ClientPatchFieldHandler::getPath, Function.identity()));
  }

  public Optional<ClientPatchFieldHandler> get(String path) {
    return Optional.ofNullable(handlersByPath.get(path));
  }

  public Set<String> supportedPaths() {
    return handlersByPath.keySet();
  }

}
