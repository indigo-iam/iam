/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2023
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
package it.infn.mw.iam.api.client.last_used.service;

import java.util.stream.Collectors;

import javax.validation.constraints.NotBlank;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.persistence.model.IamClientLastUsed;
import it.infn.mw.iam.persistence.repository.client.IamClientLastUsedRepository;

@Service
@Validated
public class DefaultClientLastUsedService implements ClientLastUsedService {

  private final IamClientLastUsedRepository repository;

  public DefaultClientLastUsedService(IamClientLastUsedRepository repository) {
    this.repository = repository;
  }

  @Override
  public ListResponseDTO<IamClientLastUsed> getAllClients(Pageable pageable) {

    Page<IamClientLastUsed> pagedResults = repository.findAll(pageable);

    ListResponseDTO.Builder<IamClientLastUsed> resultBuilder = ListResponseDTO.builder();

    return resultBuilder
      .resources(pagedResults.getContent()
        .stream()
        .collect(Collectors.toList()))
      .fromPage(pagedResults, pageable)
      .build();
  }
/* 
  void updateLastUsed(@NotBlank String clientId){
      
      ClientDetailsEntity client = clientService.findByClientId(clientId)
        .orElseThrow(ClientSuppliers.clientNotFound(clientId));
  
      IamClientLastUsed lastUsed = lastUsedRepository.findByClientId(clientId)
        .orElseGet(() -> IamClientLastUsed.builder().clientId(clientId).build());
  
      lastUsed.setClient(client);
      lastUsed.setLastUsed(new Date());
  
      lastUsedRepository.save(lastUsed);
  }
 */
}