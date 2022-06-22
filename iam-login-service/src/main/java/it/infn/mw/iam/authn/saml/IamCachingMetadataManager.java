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

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.saml2.metadata.provider.MetadataFilterChain;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.SignatureValidationFilter;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

public class IamCachingMetadataManager extends CachingMetadataManager {

  public static final Logger LOGGER = LoggerFactory.getLogger(IamCachingMetadataManager.class);

  public IamCachingMetadataManager(List<MetadataProvider> providers)
      throws MetadataProviderException {
    super(providers);
  }

  @Override
  protected void initializeProviderFilters(ExtendedMetadataDelegate p)
      throws MetadataProviderException {

    if (!(p instanceof IamExtendedMetadataDelegate)){
      super.initializeProviderFilters(p);
      return;
    }
    
    IamExtendedMetadataDelegate provider = (IamExtendedMetadataDelegate) p;

    if (provider.isTrustFiltersInitialized()) {
      LOGGER.debug(
          "Metadata provider was already initialized, "
          + "signature filter initialization will be skipped");

    } else {

      boolean requireSignature = provider.isMetadataRequireSignature();
      SignatureTrustEngine trustEngine = getTrustEngine(provider);
      SignatureValidationFilter signatureFilter = new SignatureValidationFilter(trustEngine);
      signatureFilter.setRequireSignature(requireSignature);
      
      LOGGER.debug("Created new trust manager for metadata provider {}", provider);
      
      MetadataFilter currentFilter = provider.getMetadataFilter();
      
      List<MetadataFilter> filters = new ArrayList<>();
      
      // Signature checks first!
      filters.add(signatureFilter);
      
      if (currentFilter != null){
        filters.add(currentFilter);
      }

      MetadataFilterChain chain = new MetadataFilterChain();
      chain.setFilters(filters);
      
      provider.setMetadataFilter(chain);
      
      provider.setTrustFiltersInitialized(true);
    }

  }

}
