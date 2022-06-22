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
package it.infn.mw.iam.api.group;

import static java.lang.String.format;
import static java.util.Objects.isNull;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.common.GroupDTO;
import it.infn.mw.iam.api.scim.converter.Converter;
import it.infn.mw.iam.api.scope_policy.GroupRefDTO;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@Component
public class GroupDTOConverter implements Converter<GroupDTO, IamGroup> {

  final IamGroupRepository groupRepo;

  @Autowired
  public GroupDTOConverter(IamGroupRepository repo) {
    this.groupRepo = repo;
  }

  @Override
  public IamGroup entityFromDto(GroupDTO dto) {
    IamGroup g = new IamGroup();

    if (!isNull(dto.getParent())) {
      
      IamGroup parent = groupRepo.findByUuid(dto.getParent().getUuid())
        .orElseThrow(() -> new InvalidGroupError("Parent group not found for id"));
      
      g.setName(format("%s/%s", parent.getName(), dto.getName()));
      parent.getChildrenGroups().add(g);
      g.setParentGroup(parent);
    } else {
      g.setName(dto.getName());
    }

    g.setDescription(dto.getDescription());
    return g;
  }

  @Override
  public GroupDTO dtoFromEntity(IamGroup entity) {
    GroupDTO.Builder builder = GroupDTO.builder();
    builder.name(entity.getName()).description(entity.getDescription()).id(entity.getUuid());
    if (!isNull(entity.getParentGroup())) {
      GroupRefDTO parent = new GroupRefDTO();
      parent.setUuid(entity.getParentGroup().getUuid());
      parent.setName(entity.getParentGroup().getName());
      builder.parent(parent);
    }
    return builder.build();
  }

}
