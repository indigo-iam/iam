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
package it.infn.mw.iam.core.jwt;

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

import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

@Service
public class ClientKeyCacheService {

  private static Logger logger = LoggerFactory.getLogger(ClientKeyCacheService.class);

  private JwkSetCacheService jwksUriCache;
  private SymmetricKeyJWTValidatorCacheService symmetricCache;

  private LoadingCache<JWKSet, JwtSigningAndValidationService> jwksValidators;
  private LoadingCache<JWKSet, JwtEncryptionAndDecryptionService> jwksEncrypters;

  public ClientKeyCacheService(JwkSetCacheService jwksUriCache,
      SymmetricKeyJWTValidatorCacheService symmetricCache) {

    this.jwksValidators = CacheBuilder.newBuilder()
      .expireAfterWrite(1, TimeUnit.HOURS)
      .maximumSize(100)
      .build(new JWKSetVerifierBuilder());
    this.jwksEncrypters = CacheBuilder.newBuilder()
      .expireAfterWrite(1, TimeUnit.HOURS)
      .maximumSize(100)
      .build(new JWKSetEncryptorBuilder());
  }

  public JwtSigningAndValidationService getValidator(ClientDetailsEntity client, JWSAlgorithm alg) {

    try {
      if (alg.equals(JWSAlgorithm.RS256) || alg.equals(JWSAlgorithm.RS384)
          || alg.equals(JWSAlgorithm.RS512) || alg.equals(JWSAlgorithm.ES256)
          || alg.equals(JWSAlgorithm.ES384) || alg.equals(JWSAlgorithm.ES512)
          || alg.equals(JWSAlgorithm.PS256) || alg.equals(JWSAlgorithm.PS384)
          || alg.equals(JWSAlgorithm.PS512)) {

        // asymmetric key
        if (client.getJwks() != null) {
          return jwksValidators.get(client.getJwks());
        } else if (!Strings.isNullOrEmpty(client.getJwksUri())) {
          return jwksUriCache.getValidator(client.getJwksUri());
        } else {
          return null;
        }

      } else if (alg.equals(JWSAlgorithm.HS256) || alg.equals(JWSAlgorithm.HS384)
          || alg.equals(JWSAlgorithm.HS512)) {

        return symmetricCache.getSymmetricValidator(client);
      }

      return null;

    } catch (UncheckedExecutionException | ExecutionException e) {
      logger.error("Problem loading client validator", e);
      return null;
    }
  }

  public JwtEncryptionAndDecryptionService getEncrypter(ClientDetailsEntity client) {

    try {
      if (client.getJwks() != null) {
        return jwksEncrypters.get(client.getJwks());
      } else if (!Strings.isNullOrEmpty(client.getJwksUri())) {
        return jwksUriCache.getEncrypter(client.getJwksUri());
      } else {
        return null;
      }
    } catch (UncheckedExecutionException | ExecutionException e) {
      logger.error("Problem loading client encrypter", e);
      return null;
    }

  }


  private class JWKSetEncryptorBuilder
      extends CacheLoader<JWKSet, JwtEncryptionAndDecryptionService> {

    @Override
    public JwtEncryptionAndDecryptionService load(JWKSet key) throws Exception {
      return new IamJwtEncryptionAndDecryptionService(new JwkSetKeyStore(key));
    }

  }

  private class JWKSetVerifierBuilder extends CacheLoader<JWKSet, JwtSigningAndValidationService> {

    @Override
    public JwtSigningAndValidationService load(JWKSet key) throws Exception {
      return new IamJwtSigningAndValidationService(new JwkSetKeyStore(key));
    }

  }


}
