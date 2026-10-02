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
package it.infn.mw.iam.core.jwk;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.JWKProperties;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

@SuppressWarnings("deprecation")
@Service
public class ClientKeyCacheService {

  private static Logger logger = LoggerFactory.getLogger(ClientKeyCacheService.class);

  private final IamJWKSetCacheService jwksUriCache;

  private LoadingCache<JWKSet, JWTSigningAndValidationService> jwksValidators;

  public ClientKeyCacheService(IamProperties iamProperties, IamJWKSetCacheService jwksUriCache) {
    this.jwksUriCache = jwksUriCache;
    this.jwksValidators = CacheBuilder.newBuilder()
      .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
      .maximumSize(100)
      .build(new JWKSetVerifierBuilder(iamProperties.getJwk()));
  }


  public JWTSigningAndValidationService getValidator(ClientDetailsEntity client, JWSAlgorithm alg) {

    try {
      if (IamWellKnownInfoProvider.SIGNING_ALGOS.contains(alg)) {
        if (client.getJwks() != null) {
          return jwksValidators.get(client.getJwks());
        }
        if (!Strings.isNullOrEmpty(client.getJwksUri())) {
          return jwksUriCache.getValidator(client.getJwksUri());
        }
      }
    } catch (UncheckedExecutionException | ExecutionException e) {
      logger.error("Problem loading client validator", e);
    }
    return null;
  }

  private class JWKSetVerifierBuilder extends CacheLoader<JWKSet, JWTSigningAndValidationService> {

    private final JWKProperties properties;

    public JWKSetVerifierBuilder(JWKProperties properties) {
      this.properties = properties;
    }

    @Override
    public JWTSigningAndValidationService load(JWKSet key) throws Exception {
      return new IamJWTSigningService(JwkKeyStore.from(key), properties);
    }
  }

}
