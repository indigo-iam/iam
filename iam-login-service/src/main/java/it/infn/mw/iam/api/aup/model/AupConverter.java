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
package it.infn.mw.iam.api.aup.model;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.converter.Converter;
import it.infn.mw.iam.persistence.model.IamAup;

@Service
public class AupConverter implements Converter<AupDTO, IamAup> {

  @Override
  public IamAup entityFromDto(AupDTO dto) {
    IamAup aup = new IamAup();
    aup.setCreationTime(dto.getCreationTime());
    aup.setDescription(dto.getDescription());
    aup.setLastUpdateTime(dto.getLastUpdateTime());
    aup.setSignatureValidityInDays(dto.getSignatureValidityInDays());
    aup.setUrl(dto.getUrl());
    aup.setText(dto.getText());
    return aup;
  }

  @Override
  public AupDTO dtoFromEntity(IamAup entity) {
    return new AupDTO(entity.getUrl(), entity.getText(), entity.getDescription(),
        entity.getSignatureValidityInDays(), entity.getCreationTime(), entity.getLastUpdateTime());
  }

}
