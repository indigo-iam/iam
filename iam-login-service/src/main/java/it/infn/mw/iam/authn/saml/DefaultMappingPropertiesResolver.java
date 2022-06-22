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
package it.infn.mw.iam.authn.saml;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Map;

import com.google.common.base.Splitter;
import com.google.common.collect.Maps;

import it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties.AttributeMappingProperties;
import it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties.EntityAttributeMappingProperties;

public class DefaultMappingPropertiesResolver implements MappingPropertiesResolver {

  private final AttributeMappingProperties defaultProperties;
  private final Map<String, AttributeMappingProperties> entityMappings = Maps.newHashMap();
  private final Splitter splitter = Splitter.on(',').omitEmptyStrings().trimResults();

  public DefaultMappingPropertiesResolver(AttributeMappingProperties defaultProperties,
      List<EntityAttributeMappingProperties> entityProperties) {
    checkNotNull(defaultProperties, "default properties cannot be null");
    checkNotNull(entityProperties, "entity properties cannot be null");
    this.defaultProperties = defaultProperties;
    entityProperties.forEach(this::addEntityMapping);
  }

  private void addEntityMapping(EntityAttributeMappingProperties properties) {
    splitter.split(properties.getEntityIds())
      .forEach(e -> entityMappings.put(e, properties.getMapping()));
  }

  @Override
  public AttributeMappingProperties resolveMappingProperties(String entityId) {
    return entityMappings.getOrDefault(entityId, defaultProperties);
  }

}
