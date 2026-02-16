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
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;

import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

@Service
public class SymmetricKeyJWTValidatorCacheService {

  private static final Logger logger =
      LoggerFactory.getLogger(SymmetricKeyJWTValidatorCacheService.class);

  private LoadingCache<String, JwtSigningAndValidationService> validators;

  public SymmetricKeyJWTValidatorCacheService() {
    validators = CacheBuilder.newBuilder()
      .expireAfterAccess(24, TimeUnit.HOURS)
      .maximumSize(100)
      .build(new SymmetricValidatorBuilder());
  }

  public JwtSigningAndValidationService getSymmetricValidator(ClientDetailsEntity client) {

    if (client == null) {
      logger.error("Couldn't create symmetric validator for null client");
      return null;
    }

    if (Strings.isNullOrEmpty(client.getClientSecret())) {
      logger.error("Couldn't create symmetric validator for client " + client.getClientId()
          + " without a client secret");
      return null;
    }

    try {
      return validators.get(client.getClientSecret());
    } catch (UncheckedExecutionException | ExecutionException e) {
      logger.error("Problem loading client validator", e);
    }
    return null;
  }

  public class SymmetricValidatorBuilder
      extends CacheLoader<String, JwtSigningAndValidationService> {
    @Override
    public JwtSigningAndValidationService load(String key) throws Exception {

      JWK jwk = new OctetSequenceKey.Builder(Base64URL.encode(key)).keyUse(KeyUse.SIGNATURE)
        .keyID("SYMMETRIC-KEY")
        .build();
      return new IamJwtSigningAndValidationService(new JwkSetKeyStore(new JWKSet(jwk)));
    }
  }

}
