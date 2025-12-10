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
package it.infn.mw.iam.authn.saml.util;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.SAMLCredential;

import it.infn.mw.iam.persistence.model.IamSamlId;

public class ChainedCollectingSamlIdResolver implements SamlUserIdentifierResolver {

  public static final Logger LOG = LoggerFactory.getLogger(ChainedCollectingSamlIdResolver.class);

  private final List<SamlUserIdentifierResolver> resolvers;

  public ChainedCollectingSamlIdResolver(List<SamlUserIdentifierResolver> resolvers) {
    this.resolvers = resolvers;
  }

  @Override
  public SamlUserIdentifierResolutionResult resolveSamlUserIdentifier(
      SAMLCredential samlCredential) {

    List<IamSamlId> collectedIds = new ArrayList<>();
    List<String> errorMessages = new ArrayList<>();

    for (SamlUserIdentifierResolver resolver : resolvers) {
      LOG.debug("Attempting SAML user id resolution with resolver {}",
          resolver.getClass().getName());

      SamlUserIdentifierResolutionResult result =
          resolver.resolveSamlUserIdentifier(samlCredential);

      if (!result.getResolvedIds().isEmpty()) {
        collectedIds.addAll(result.getResolvedIds());
        LOG.debug("Resolved SAML user id: {}", result.getResolvedIds().get(0).getAttributeId());
      }

      if (!result.getErrorMessages().isEmpty()) {
        errorMessages.addAll(result.getErrorMessages());
        if (LOG.isDebugEnabled()) {
          LOG.debug("SAML user id resolution with resolver {} failed with the following errors",
              resolver.getClass().getName());
          result.getErrorMessages().forEach(LOG::debug);
        }
      }
    }

    if (!collectedIds.isEmpty()) {
      return SamlUserIdentifierResolutionResult.success(collectedIds);
    }

    LOG
      .debug("All configured user id resolvers could not resolve the user id from SAML credential");
    return SamlUserIdentifierResolutionResult.failure(errorMessages);
  }
}
