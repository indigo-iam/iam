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

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.requests.model.CertLinkRequestDTO;
import it.infn.mw.iam.api.scim.converter.X509CertificateParser;
import it.infn.mw.iam.persistence.model.IamCertLinkRequest;
import it.infn.mw.iam.persistence.model.IamX509Certificate;

@Service
public class CertLinkRequestConverter {

  @Autowired
  private X509CertificateParser parser;

  public CertLinkRequestDTO dtoFromEntity(IamCertLinkRequest entity) {
    CertLinkRequestDTO dto = new CertLinkRequestDTO();

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

  public IamX509Certificate certificateFromRequest(CertLinkRequestDTO requestDto) {

    IamX509Certificate cert;

    if (requestDto.getPemEncodedCertificate() != null) {
      cert = parser.parseCertificateFromString(requestDto.getPemEncodedCertificate());
    } else {
      cert = new IamX509Certificate();
      cert.setCertificate(requestDto.getPemEncodedCertificate());
      cert.setSubjectDn(requestDto.getSubjectDn());
      cert.setIssuerDn(requestDto.getIssuerDn());
    }

    Date now = new Date();
    cert.setCreationTime(now);
    cert.setLastUpdateTime(now);
    cert.setLabel(requestDto.getLabel());
    return cert;
  }
}
