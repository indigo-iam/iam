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
package it.infn.mw.iam.api.common;

import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.converter.Converter;
import it.infn.mw.iam.persistence.model.IamAttribute;

@Component
public class AttributeDTOConverter implements Converter<AttributeDTO, IamAttribute> {

  public AttributeDTOConverter() {
    // empty on purpose
  }

  @Override
  public IamAttribute entityFromDto(AttributeDTO dto) {
    
    IamAttribute attribute = new IamAttribute();
    attribute.setName(dto.getName());
    attribute.setValue(dto.getValue());
    return attribute;
  }

  @Override
  public AttributeDTO dtoFromEntity(IamAttribute entity) {
    
    AttributeDTO dto = new AttributeDTO();
    dto.setName(entity.getName());
    dto.setValue(entity.getValue());
    return dto;
    
  }

}
