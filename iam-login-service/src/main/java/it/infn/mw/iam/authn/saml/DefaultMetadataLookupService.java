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

import static com.google.common.base.Strings.isNullOrEmpty;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ObservableMetadataProvider;
import org.opensaml.samlext.saml2mdui.UIInfo;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Component;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.saml.model.IdpDescription;

@Component
@Profile("saml")
public class DefaultMetadataLookupService implements MetadataLookupService, ObservableMetadataProvider.Observer {

  private static final int MAX_RESULTS = 20;
  private static final Logger LOG = LoggerFactory.getLogger(DefaultMetadataLookupService.class);

  Set<IdpDescription> descriptions = new HashSet<>();
  ReadWriteLock lock = new ReentrantReadWriteLock(true);

  MetadataManager metadataManager;

  @Autowired
  public DefaultMetadataLookupService(MetadataManager manager) {
    this.metadataManager = manager;
    manager.getObservers().add(this);
    refreshMetadata();
  }

  private void initializeMetadataSet() throws MetadataProviderException {

    final Instant startTime = Instant.now();
    LOG.debug("Initializing IdP descriptor list from metadata");
    
    Set<IdpDescription> newDescriptions = new HashSet<>();

    for (String idpName : metadataManager.getIDPEntityNames()) {

      IdpDescription idpDescription =
          descriptionFromMetadata(metadataManager.getEntityDescriptor(idpName));

      LOG.debug("Adding IdP description: {}", idpDescription);
      newDescriptions.add(idpDescription);
    }

    try {
      lock.writeLock().lock();
      descriptions = newDescriptions;
    } finally {
      lock.writeLock().unlock();
      final Duration d = Duration.between(startTime, Instant.now());
      LOG.debug("Idp descriptor list initialization took {} msec", d.toMillis());
    }

  }

  private IdpDescription descriptionFromMetadata(EntityDescriptor descriptor) {
    IdpDescription result = new IdpDescription();
    result.setEntityId(descriptor.getEntityID());

    IDPSSODescriptor idpDesc = descriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    if (idpDesc != null && idpDesc.getExtensions() != null) {

      for (final XMLObject object : idpDesc.getExtensions()
        .getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME)) {
        if (object instanceof UIInfo) {
          UIInfo uiInfo = (UIInfo) object;

          if (!uiInfo.getDisplayNames().isEmpty()) {
            result.setOrganizationName(uiInfo.getDisplayNames().get(0).getName().getLocalString());
          }
        }
      }
    }

    if (isNullOrEmpty(result.getOrganizationName())) {
      result.setOrganizationName(result.getEntityId());
    }

    return result;
  }


  private Optional<List<IdpDescription>> lookupByEntityId(String text) {
    // Try entityId match
    try {

      EntityDescriptor entityDescriptor = metadataManager.getEntityDescriptor(text);
      if (entityDescriptor != null) {
        return Optional.of(List.of(descriptionFromMetadata(entityDescriptor)));
      }

    } catch (MetadataProviderException e) {
      throw new SamlMetadataError(e.getMessage(), e);
    }

    return Optional.empty();
  }

  @Override
  public List<IdpDescription> lookupIdp(String text) {

    List<IdpDescription> result = new ArrayList<>();

    lookupByEntityId(text).ifPresent(result::addAll);

    if (!result.isEmpty()) {
      return result;
    }

    try {
      lock.readLock().lock();
      return descriptions.stream()
        .filter(p -> p.getOrganizationName().toLowerCase().contains(text.toLowerCase()))
        .limit(MAX_RESULTS)
        .collect(Collectors.toList());
    } finally {
      lock.readLock().unlock();
    }
  }

  @Override
  public List<IdpDescription> listIdps() {
    Set<String> idpNames = metadataManager.getIDPEntityNames();

    List<IdpDescription> results = new ArrayList<>();

    for (String idpName : idpNames) {
      try {
        IdpDescription desc = descriptionFromMetadata(metadataManager.getEntityDescriptor(idpName));

        if (!Strings.isNullOrEmpty(desc.getOrganizationName())) {
          results.add(desc);
        }

      } catch (MetadataProviderException e) {
        LOG.warn("Error accessing metadata for entity: {}", idpName, e);
      }

    }

    return results;

  }

  @Override
  public void refreshMetadata() {
    try {
      initializeMetadataSet();
    } catch (MetadataProviderException e) {
      throw new SamlMetadataError(e);
    }
  }

  @Override
  public void onEvent(MetadataProvider provider) {
    refreshMetadata();
  }

}
