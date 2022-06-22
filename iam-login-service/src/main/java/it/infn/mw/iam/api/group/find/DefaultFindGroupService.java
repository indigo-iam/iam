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
package it.infn.mw.iam.api.group.find;

import static it.infn.mw.iam.api.utils.FindUtils.responseFromPage;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.converter.GroupConverter;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimListResponse.ScimListResponseBuilder;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@Service
public class DefaultFindGroupService implements FindGroupService {

  final GroupConverter converter;
  final IamGroupRepository repo;

  @Autowired
  public DefaultFindGroupService(GroupConverter converter, IamGroupRepository repo) {
    this.converter = converter;
    this.repo = repo;
  }

  @Override
  public ScimListResponse<ScimGroup> findGroupByName(String name) {
    Optional<IamGroup> maybeGroup = repo.findByName(name);

    ScimListResponseBuilder<ScimGroup> builder = ScimListResponse.builder();

    maybeGroup.ifPresent(a -> builder.singleResource(converter.dtoFromEntity(a)));
    return builder.build();
  }

  @Override
  public ScimListResponse<ScimGroup> findGroupByLabel(String labelName, String labelValue,
      Pageable pageable) {

    Page<IamGroup> results = repo.findByLabelNameAndValue(labelName, labelValue, pageable);
    return responseFromPage(results, converter, pageable);
  }

  @Override
  public ScimListResponse<ScimGroup> findUnsubscribedGroupsForAccount(String accountUuid,
      String filter, Pageable pageable) {

    Page<IamGroup> results;

    Optional<String> nameFilter = Optional.ofNullable(filter);

    if (nameFilter.isPresent()) {
      results = repo.findUnsubscribedGroupsForAccountWithNameLike(accountUuid, nameFilter.get(),
          pageable);
    } else {
      results = repo.findUnsubscribedGroupsForAccount(accountUuid, pageable);
    }

    return responseFromPage(results, converter, pageable);
  }

}
