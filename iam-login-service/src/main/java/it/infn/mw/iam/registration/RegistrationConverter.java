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
package it.infn.mw.iam.registration;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.common.LabelDTO;
import it.infn.mw.iam.api.common.LabelDTOConverter;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@Service
public class RegistrationConverter {

  final LabelDTOConverter labelConverter;

  @Autowired
  public RegistrationConverter(LabelDTOConverter labelConverter) {
    this.labelConverter = labelConverter;
  }

  public RegistrationRequestDto fromEntity(final IamRegistrationRequest entity) {

    RegistrationRequestDto dto = new RegistrationRequestDto();
    dto.setUuid(entity.getUuid());
    dto.setCreationTime(entity.getCreationTime());
    dto.setStatus(entity.getStatus().name());
    dto.setLastUpdateTime(entity.getLastUpdateTime());
    dto.setUsername(entity.getAccount().getUsername());
    dto.setGivenname(entity.getAccount().getUserInfo().getGivenName());
    dto.setFamilyname(entity.getAccount().getUserInfo().getFamilyName());
    dto.setEmail(entity.getAccount().getUserInfo().getEmail());
    dto.setAccountId(entity.getAccount().getUuid());
    dto.setNotes(entity.getNotes());

    List<LabelDTO> labels = Lists.newArrayList();

    for (IamLabel label : entity.getLabels()) {
      labels.add(labelConverter.dtoFromEntity(label));
    }

    dto.setLabels(labels);
    return dto;
  }

  public IamRegistrationRequest toEntity(final RegistrationRequestDto dto) {

    IamUserInfo userInfo = new IamUserInfo();
    userInfo.setFamilyName(dto.getFamilyname());
    userInfo.setGivenName(dto.getGivenname());
    userInfo.setEmail(dto.getEmail());
    userInfo.setBirthdate(dto.getBirthdate());

    IamAccount account = new IamAccount();
    account.setUsername(dto.getUsername());
    account.setUserInfo(userInfo);
    account.setUuid(dto.getAccountId());

    IamRegistrationRequest entity = new IamRegistrationRequest();
    entity.setUuid(dto.getUuid());
    entity.setCreationTime(dto.getCreationTime());
    entity.setLastUpdateTime(entity.getLastUpdateTime());
    entity.setStatus(IamRegistrationRequestStatus.valueOf(dto.getStatus()));
    entity.setAccount(account);
    entity.setNotes(dto.getNotes());

    Set<IamLabel> labels =
        dto.getLabels().stream().map(labelConverter::entityFromDto).collect(Collectors.toSet());

    entity.setLabels(labels);

    return entity;
  }

}
