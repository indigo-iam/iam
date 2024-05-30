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

import it.infn.mw.iam.api.requests.model.CertLinkRequestDto;
import it.infn.mw.iam.persistence.model.IamCertLinkRequest;

@Service
public class CertLinkRequestConverter {

  public CertLinkRequestDto fromEntity(IamCertLinkRequest entity) {
    CertLinkRequestDto dto = new CertLinkRequestDto();
    
    dto.setUuid(entity.getUuid());
    dto.setUsername(entity.getAccount().getUsername());
    dto.setUserUuid(entity.getAccount().getUuid());
    dto.setUserFullName(entity.getAccount().getUserInfo().getName());
    dto.setSubjectDn(entity.getCertificate().getSubjectDn());
    dto.setIssuerDn(entity.getCertificate().getIssuerDn());
    dto.setLabel(entity.getCertificate().getLabel());
    dto.setStatus(entity.getStatus().name());
    dto.setNotes(entity.getNotes());
    dto.setMotivation(entity.getMotivation());
    dto.setCreationTime(entity.getCreationTime());
    dto.setLastUpdateTime(entity.getLastUpdateTime());
    
    return dto;
  }
}
