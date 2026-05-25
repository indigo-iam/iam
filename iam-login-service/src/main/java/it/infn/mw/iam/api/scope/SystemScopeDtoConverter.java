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
package it.infn.mw.iam.api.scope;

import org.mitre.oauth2.model.SystemScope;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.converter.Converter;

@Component
public class SystemScopeDtoConverter implements Converter<SystemScopeDto, SystemScope>{

  @Override
  public SystemScope entityFromDto(SystemScopeDto dto) {
    SystemScope entity = new SystemScope();
    entity.setId(dto.getId());
    entity.setDefaultScope(dto.isDefaultScope());
    entity.setDescription(dto.getDescription());
    entity.setIcon(dto.getIcon());
    entity.setRestricted(dto.isRestricted());
    entity.setValue(dto.getValue());
    entity.setStructured(dto.isStructured());
    return entity;
  }

  @Override
  public SystemScopeDto dtoFromEntity(SystemScope entity) {
    return SystemScopeDto.builder()
      .id(entity.getId())
      .value(entity.getValue())
      .defaultScope(entity.isDefaultScope())
      .description(entity.getDescription())
      .icon(entity.getIcon())
      .restricted(entity.isRestricted())
      .structured(entity.isStructured())
      .build();
  }

}
