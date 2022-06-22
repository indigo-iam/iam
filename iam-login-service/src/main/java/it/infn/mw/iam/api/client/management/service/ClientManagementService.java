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
package it.infn.mw.iam.api.client.management.service;

import java.text.ParseException;
import java.util.Optional;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import org.springframework.data.domain.Pageable;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scope_policy.validation.IamAccountId;

public interface ClientManagementService {

  ListResponseDTO<RegisteredClientDTO> retrieveAllDynamicallyRegisteredClients(
      @NotNull Pageable pageable);

  ListResponseDTO<RegisteredClientDTO> retrieveAllClients(@NotNull Pageable pageable);

  Optional<RegisteredClientDTO> retrieveClientByClientId(@NotBlank String clientId);

  RegisteredClientDTO saveNewClient(@NotNull @Valid RegisteredClientDTO client)
      throws ParseException;

  RegisteredClientDTO updateClient(@NotBlank String clientId,
      @NotNull @Valid RegisteredClientDTO client) throws ParseException;

  RegisteredClientDTO generateNewClientSecret(@NotBlank String clientId);

  RegisteredClientDTO rotateRegistrationAccessToken(@NotBlank String clientId);

  void deleteClientByClientId(@NotBlank String clientId);

  ListResponseDTO<ScimUser> getClientOwners(@NotBlank String clientId, @NotNull Pageable pageable);

  void assignClientOwner(@NotBlank String clientId, @IamAccountId String accountId);

  void removeClientOwner(@NotBlank String clientId, @IamAccountId String accountId);


}
