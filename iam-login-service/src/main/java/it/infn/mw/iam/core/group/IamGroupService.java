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
package it.infn.mw.iam.core.group;

import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamLabel;

public interface IamGroupService {
  
  long countAllGroups();

  Page<IamGroup> findAll(Pageable page);

  Page<IamGroup> findSubgroups(IamGroup group, Pageable page);
  
  Optional<IamGroup> findByNameWithDifferentId(String name, String uuid);
  Optional<IamGroup> findByName(String name);
  Optional<IamGroup> findByUuid(String uuid);

  IamGroup save(IamGroup g);
  
  String groupManagerAuthority(IamGroup g);
  
  IamGroup createGroup(IamGroup g);
  
  IamGroup updateGroup(IamGroup oldGroup, IamGroup newGroup);
  
  IamGroup deleteGroupByUuid(String uuid);
  
  IamGroup deleteGroup(IamGroup g);
  
  IamGroup addLabel(IamGroup g, IamLabel l);
  
  IamGroup deleteLabel(IamGroup g, IamLabel l);

  IamGroup setDescription(IamGroup g, String description);

  void touchGroup(IamGroup g);

}
