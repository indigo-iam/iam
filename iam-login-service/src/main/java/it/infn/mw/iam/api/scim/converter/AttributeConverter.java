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
package it.infn.mw.iam.api.scim.converter;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimAttribute;
import it.infn.mw.iam.persistence.model.IamAttribute;

@Service
public class AttributeConverter implements Converter<ScimAttribute, IamAttribute> {

  @Override
  public IamAttribute entityFromDto(ScimAttribute dto) {

    IamAttribute entity = new IamAttribute();
    entity.setName(dto.getName());
    entity.setValue(dto.getValue());
    return entity;
  }

  @Override
  public ScimAttribute dtoFromEntity(IamAttribute entity) {

    return ScimAttribute.builder().withName(entity.getName()).withVaule(entity.getValue()).build();
  }

}
