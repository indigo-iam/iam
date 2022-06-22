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
package it.infn.mw.iam.api.account.search.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import it.infn.mw.iam.api.common.PagedResourceService;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@Service
public class DefaultPagedGroupsService implements PagedResourceService<IamGroup> {

  @Autowired
  private IamGroupRepository groupRepository;

  @Override
  public Page<IamGroup> getPage(Pageable op) {
    return groupRepository.findAll(op);
  }

  @Override
  public long count() {
    return groupRepository.count();
  }

  @Override
  public Page<IamGroup> getPage(Pageable op, String filter) {

    return groupRepository.findByNameIgnoreCaseContainingOrUuidIgnoreCaseContaining(filter, filter, op);
  }

  @Override
  public long count(String filter) {

    return groupRepository.countByNameIgnoreCaseContainingOrUuidIgnoreCaseContaining(filter, filter);
  }

}
