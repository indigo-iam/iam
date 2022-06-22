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
package it.infn.mw.iam.api.requests;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.requests.model.GroupRequestDto;
import it.infn.mw.iam.persistence.model.IamGroupRequest;

@Service
public class GroupRequestConverter {

  public GroupRequestDto fromEntity(IamGroupRequest iamGroupRequest) {
    GroupRequestDto groupRequest = new GroupRequestDto();
    
    groupRequest.setUuid(iamGroupRequest.getUuid());
    groupRequest.setUsername(iamGroupRequest.getAccount().getUsername());
    groupRequest.setUserUuid(iamGroupRequest.getAccount().getUuid());
    groupRequest.setUserFullName(iamGroupRequest.getAccount().getUserInfo().getName());
    groupRequest.setGroupName(iamGroupRequest.getGroup().getName());
    groupRequest.setGroupUuid(iamGroupRequest.getGroup().getUuid());
    groupRequest.setStatus(iamGroupRequest.getStatus().name());
    groupRequest.setNotes(iamGroupRequest.getNotes());
    groupRequest.setMotivation(iamGroupRequest.getMotivation());
    groupRequest.setCreationTime(iamGroupRequest.getCreationTime());
    groupRequest.setLastUpdateTime(iamGroupRequest.getLastUpdateTime());

    return groupRequest;
  }
}
