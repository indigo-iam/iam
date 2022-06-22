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

import java.util.stream.Collectors;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.search.ClientSearchForm;
import it.infn.mw.iam.api.client.service.ClientConverter;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.PagingUtils;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.error.NoAuthenticatedUserError;
import it.infn.mw.iam.api.common.form.PaginatedRequestForm;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountClient;
import it.infn.mw.iam.persistence.repository.client.ClientSpecs;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Service
@Validated
public class DefaultClientSearchService implements ClientSearchService {

  public static final int MAX_PAGE_SIZE = 100;

  private final IamClientRepository clientRepo;
  private final IamAccountClientRepository accountClientRepo;
  private final AccountUtils accountUtils;
  private final ClientConverter converter;

  @Autowired
  public DefaultClientSearchService(IamClientRepository clientRepo,
      IamAccountClientRepository accountClientRepo, AccountUtils accountUtils,
      ClientConverter converter) {
    this.clientRepo = clientRepo;
    this.accountClientRepo = accountClientRepo;
    this.converter = converter;
    this.accountUtils = accountUtils;
  }

  private Sort parseSortParameters(ClientSearchForm searchForm) {
    Sort sort;

    if (searchForm.getSortDirection() != null) {
      if (searchForm.getSortProperties() != null) {
        sort = Sort.by(searchForm.getSortDirection(), searchForm.getSortProperties());
      } else {
        sort = Sort.by(searchForm.getSortDirection(), "clientId");
      }
    } else {
      sort = Sort.by(Direction.ASC, "clientId");
    }

    return sort;
  }

  @Override
  public ListResponseDTO<RegisteredClientDTO> searchClients(ClientSearchForm clientSearchForm) {

    Pageable pageable = PagingUtils.buildPageRequest(clientSearchForm.getCount(),
        clientSearchForm.getStartIndex(), MAX_PAGE_SIZE, parseSortParameters(clientSearchForm));

    Specification<ClientDetailsEntity> spec = ClientSpecs.fromSearchForm(clientSearchForm);
    Page<ClientDetailsEntity> pagedResults = clientRepo.findAll(spec, pageable);

    ListResponseDTO.Builder<RegisteredClientDTO> resultBuilder = ListResponseDTO.builder();

    return resultBuilder
      .resources(pagedResults.getContent()
        .stream()
        .map(converter::registeredClientDtoFromEntity)
        .collect(Collectors.toList()))
      .fromPage(pagedResults, pageable)
      .build();
  }

  @Override
  public ListResponseDTO<RegisteredClientDTO> findOwnedClients(
      PaginatedRequestForm form) {

    IamAccount account =
        accountUtils.getAuthenticatedUserAccount().orElseThrow(NoAuthenticatedUserError::new);

    Pageable pageable = PagingUtils.buildPageRequest(form.getCount(), form.getStartIndex(),
        MAX_PAGE_SIZE);

    Page<IamAccountClient> pagedResults = 
        accountClientRepo.findByAccount(account, pageable);

    ListResponseDTO.Builder<RegisteredClientDTO> resultBuilder = ListResponseDTO.builder();

    return resultBuilder
      .resources(pagedResults.getContent()
        .stream()
        .map(IamAccountClient::getClient)
        .map(converter::registeredClientDtoFromEntity)
        .collect(Collectors.toList()))
      .fromPage(pagedResults, pageable)
      .build();
  }


}
