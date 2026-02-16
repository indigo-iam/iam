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
import org.springframework.web.client.RestTemplate;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.authn.oidc.RestTemplateFactory;

public class IamJwkSetCacheService implements JwkSetCacheService {

  public static final String KEY_MATERIAL_ERROR_TEMPLATE =
      "Could not retrieve key material from {}";
  public static final Logger LOG = LoggerFactory.getLogger(IamJwkSetCacheService.class);

  private LoadingCache<String, JwtSigningAndValidationService> validators;
  private LoadingCache<String, JwtEncryptionAndDecryptionService> encrypters;

  public IamJwkSetCacheService(RestTemplateFactory rtf, int maxCacheSize, int expirationTime,
      TimeUnit timeUnit) {

    this.validators = CacheBuilder.newBuilder()
      .expireAfterWrite(expirationTime, timeUnit)
      .maximumSize(maxCacheSize)
      .build(new JwkSetVerifierFetcher(rtf));

    this.encrypters = CacheBuilder.newBuilder()
      .expireAfterWrite(expirationTime, timeUnit)
      .maximumSize(maxCacheSize)
      .build(new JwkSetEncryptorFetcher(rtf));
  }


  @Override
  public JwtSigningAndValidationService getValidator(String jwksUri) {

    try {
      return validators.get(jwksUri);
    } catch (UncheckedExecutionException | ExecutionException e) {
      LOG.error(KEY_MATERIAL_ERROR_TEMPLATE, jwksUri);
      if (LOG.isDebugEnabled()) {
        LOG.debug(KEY_MATERIAL_ERROR_TEMPLATE, jwksUri, e);
      }
      return null;
    }
  }

  @Override
  public JwtEncryptionAndDecryptionService getEncrypter(String jwksUri) {
    try {
      return encrypters.get(jwksUri);
    } catch (UncheckedExecutionException | ExecutionException e) {
      LOG.error(KEY_MATERIAL_ERROR_TEMPLATE, jwksUri);
      if (LOG.isDebugEnabled()) {
        LOG.debug(KEY_MATERIAL_ERROR_TEMPLATE, jwksUri, e);
      }
      return null;
    }
  }

  public static class JwkSetEncryptorFetcher
      extends CacheLoader<String, JwtEncryptionAndDecryptionService> {

    final RestTemplateFactory rtf;

    public JwkSetEncryptorFetcher(RestTemplateFactory rtf) {
      this.rtf = rtf;
    }

    @Override
    public JwtEncryptionAndDecryptionService load(String key) throws Exception {
      
      RestTemplate rt = rtf.newRestTemplate();
      
      String jsonString = rt.getForObject(key, String.class);
      JWKSet jwkSet = JWKSet.parse(jsonString);

      JwkSetKeyStore keyStore = new JwkSetKeyStore(jwkSet);

      return new IamJwtEncryptionAndDecryptionService(keyStore);
    }
  }

  public static class JwkSetVerifierFetcher
      extends CacheLoader<String, JwtSigningAndValidationService> {

    final RestTemplateFactory rtf;

    public JwkSetVerifierFetcher(RestTemplateFactory rtf) {
      this.rtf = rtf;
    }

    @Override
    public JwtSigningAndValidationService load(String key) throws Exception {
      
      RestTemplate rt = rtf.newRestTemplate();
      
      String jsonString = rt.getForObject(key, String.class);
      JWKSet jwkSet = JWKSet.parse(jsonString);

      JwkSetKeyStore keyStore = new JwkSetKeyStore(jwkSet);

      return new IamJwtSigningAndValidationService(keyStore);
    }
  }
}
