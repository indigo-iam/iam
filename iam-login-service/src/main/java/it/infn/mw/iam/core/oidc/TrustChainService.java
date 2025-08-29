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
package it.infn.mw.iam.core.oidc;

import java.util.List;
import java.util.Optional;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.config.TrustChainCache;

@Service
@Profile("openid-federation")
public class TrustChainService {

  private final TrustChainResolver resolver;
  private final TrustChainValidator validator;
  private final TrustChainCache trustChainCache;

  public TrustChainService(TrustChainResolver resolver, TrustChainValidator validator,
      TrustChainCache trustChainCache) {
    this.resolver = resolver;
    this.validator = validator;
    this.trustChainCache = trustChainCache;
  }

  public Optional<TrustChain> getOrResolve(String entityId) throws BadJOSEException, JOSEException {
    Optional<TrustChain> cachedChain = trustChainCache.get(entityId);
    if (cachedChain.isEmpty()) {
      return cachedChain;
    }
    try {
      List<EntityStatement> chain = resolver.resolveFromEntityId(entityId);
      TrustChain validated = validator.validate(chain);
      trustChainCache.put(entityId, validated);
      return Optional.of(validated);
    } catch (InvalidTrustChainException e) {
      return Optional.empty();
    }
  }

  public TrustChain validateFromEntityConfiguration(EntityStatement ec)
      throws InvalidTrustChainException, BadJOSEException, JOSEException {
    List<EntityStatement> chain = resolver.resolveFromEntityConfiguration(ec);
    return validator.validate(chain);
  }

  public TrustChain validateFromProvidedChain(List<EntityStatement> providedChain)
      throws InvalidTrustChainException, BadJOSEException, JOSEException {
    return validator.validate(providedChain);
  }
}
