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
package it.infn.mw.iam.api.client.search.service;

import javax.validation.Valid;

import it.infn.mw.iam.api.client.search.ClientSearchForm;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.form.PaginatedRequestForm;

public interface ClientSearchService {

  String NOT_NULL_MSG = "must not be null";

  ListResponseDTO<RegisteredClientDTO> searchClients(
      @Valid ClientSearchForm clientSearchForm);

  ListResponseDTO<RegisteredClientDTO> findOwnedClients(PaginatedRequestForm paginatedRequest);
}
