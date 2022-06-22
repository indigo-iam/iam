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
package it.infn.mw.iam.authn.saml.util.metadata;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.FilterException;
import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractMetadataFilter implements MetadataFilter {
  
  public static final Logger LOG = LoggerFactory.getLogger(AbstractMetadataFilter.class);

  protected abstract ValidationResult validateEntityDescriptor(EntityDescriptor descriptor);

  protected boolean entitiesDescriptorIsEmpty(EntitiesDescriptor descriptor) {
    return (descriptor.getEntitiesDescriptors() == null
        || descriptor.getEntitiesDescriptors().isEmpty())
        && (descriptor.getEntityDescriptors() == null
            || descriptor.getEntityDescriptors().isEmpty());
  }


  protected void filterEntityDescriptor(EntityDescriptor entity) throws FilterException {
    ValidationResult result = validateEntityDescriptor(entity);

    if (!result.isValid()) {
      throw new FilterException(result.getMessage());
    }
  }

  protected void filterEntitiesDescriptor(EntitiesDescriptor entities) throws FilterException {

    List<EntityDescriptor> failedValidationEntities = new ArrayList<>();
    List<String> failedValidationMessages = new ArrayList<>();

    if (entities.getEntityDescriptors() != null) {

      for (EntityDescriptor d : entities.getEntityDescriptors()) {

        ValidationResult result = validateEntityDescriptor(d);

        if (!result.isValid()) {
          failedValidationEntities.add(d);
          failedValidationMessages.add(result.getMessage());
        }
      }

      entities.getEntityDescriptors().removeAll(failedValidationEntities);
      failedValidationMessages.forEach(LOG::debug);
    }

    List<EntitiesDescriptor> entitiesDescriptors = entities.getEntitiesDescriptors();

    if (entitiesDescriptors != null && !entitiesDescriptors.isEmpty()) {
      List<EntitiesDescriptor> emptyEntitiesDescriptors = new ArrayList<>();
      for (EntitiesDescriptor ed : entitiesDescriptors) {
        filterEntitiesDescriptor(ed);
        if (entitiesDescriptorIsEmpty(ed)) {
          emptyEntitiesDescriptors.add(ed);
        }
      }
      entitiesDescriptors.removeAll(emptyEntitiesDescriptors);
    }
  }

  @Override
  public void doFilter(XMLObject metadata) throws FilterException {
    if (metadata == null) {
      throw new FilterException("Cannot filter null metadata");
    }
    if (metadata instanceof EntitiesDescriptor) {
      filterEntitiesDescriptor((EntitiesDescriptor) metadata);
    } else if (metadata instanceof EntityDescriptor) {
      filterEntityDescriptor((EntityDescriptor) metadata);
    } else {
      throw new FilterException("XMLObject is not a EntityDescriptor or and EntitiesDescriptor");
    }
  }
}
