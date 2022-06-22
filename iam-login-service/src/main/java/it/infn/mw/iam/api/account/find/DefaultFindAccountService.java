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
package it.infn.mw.iam.api.account.find;

import static it.infn.mw.iam.api.utils.FindUtils.responseFromPage;

import java.util.Optional;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimListResponse.ScimListResponseBuilder;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@Transactional
@Service
public class DefaultFindAccountService implements FindAccountService {

  private final IamAccountRepository repo;
  private final IamGroupRepository groupRepo;
  private final UserConverter converter;

  @Autowired
  public DefaultFindAccountService(IamAccountRepository repo, IamGroupRepository groupRepo,
      UserConverter converter) {
    this.repo = repo;
    this.groupRepo = groupRepo;
    this.converter = converter;
  }

  @Override
  public ScimListResponse<ScimUser> findAccountByLabel(String labelName, String labelValue,
      Pageable pageable) {

    Page<IamAccount> results = repo.findByLabelNameAndValue(labelName, labelValue, pageable);
    return responseFromPage(results, converter, pageable);

  }


  @Override
  public ScimListResponse<ScimUser> findAccountByEmail(String emailAddress) {
    Optional<IamAccount> account = repo.findByEmail(emailAddress);

    ScimListResponseBuilder<ScimUser> builder = ScimListResponse.builder();
    account.ifPresent(a -> builder.singleResource(converter.dtoFromEntity(a)));
    return builder.build();
  }

  @Override
  public ScimListResponse<ScimUser> findAccountByUsername(String username) {
    Optional<IamAccount> account = repo.findByUsername(username);
    ScimListResponseBuilder<ScimUser> builder = ScimListResponse.builder();
    account.ifPresent(a -> builder.singleResource(converter.dtoFromEntity(a)));
    return builder.build();
  }

  @Override
  public ScimListResponse<ScimUser> findInactiveAccounts(Pageable pageable) {

    Page<IamAccount> results = repo.findInactiveAccounts(pageable);
    return responseFromPage(results, converter, pageable);
  }

  @Override
  public ScimListResponse<ScimUser> findActiveAccounts(Pageable pageable) {

    Page<IamAccount> results = repo.findActiveAccounts(pageable);
    return responseFromPage(results, converter, pageable);

  }

  @Override
  public ScimListResponse<ScimUser> findAccountByGroupName(String groupName, Pageable pageable) {
    IamGroup group = groupRepo.findByName(groupName).orElseThrow(groupNotFoundError(groupName));
    Page<IamAccount> results = repo.findByGroupUuid(group.getUuid(), pageable);
    return responseFromPage(results, converter, pageable);
  }

  @Override
  public ScimListResponse<ScimUser> findAccountByGroupUuid(String groupUuid, Pageable pageable) {
    IamGroup group = groupRepo.findByUuid(groupUuid).orElseThrow(groupNotFoundError(groupUuid));
    Page<IamAccount> results = repo.findByGroupUuid(group.getUuid(), pageable);
    return responseFromPage(results, converter, pageable);
  }

  private Supplier<IllegalArgumentException> groupNotFoundError(String groupNameOrUuid) {
    return () -> new IllegalArgumentException("Group does not exist: " + groupNameOrUuid);
  }

  @Override
  public ScimListResponse<ScimUser> findAccountByCertificateSubject(String certSubject) {
    Optional<IamAccount> account = repo.findByCertificateSubject(certSubject);
    ScimListResponseBuilder<ScimUser> builder = ScimListResponse.builder();
    account.ifPresent(a -> builder.singleResource(converter.dtoFromEntity(a)));
    return builder.build();
  }

  @Override
  public ScimListResponse<ScimUser> findAccountNotInGroup(String groupUuid,
      Pageable pageable) {
    IamGroup group = groupRepo.findByUuid(groupUuid).orElseThrow(groupNotFoundError(groupUuid));
    Page<IamAccount> results = repo.findNotInGroup(group.getUuid(), pageable);
    return responseFromPage(results, converter, pageable);
  }

  @Override
  public ScimListResponse<ScimUser> findAccountNotInGroupWithFilter(String groupUuid, String filter,
      Pageable pageable) {
    IamGroup group = groupRepo.findByUuid(groupUuid).orElseThrow(groupNotFoundError(groupUuid));
    Page<IamAccount> results = repo.findNotInGroupWithFilter(group.getUuid(), filter, pageable);
    return responseFromPage(results, converter, pageable);
  }

  @Override
  public ScimListResponse<ScimUser> findAccountByGroupUuidWithFilter(String groupUuid,
      String filter, Pageable pageable) {
    IamGroup group = groupRepo.findByUuid(groupUuid).orElseThrow(groupNotFoundError(groupUuid));
    Page<IamAccount> results = repo.findByGroupUuidWithFilter(group.getUuid(), filter, pageable);
    return responseFromPage(results, converter, pageable);
  }
}
