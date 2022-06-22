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

import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestTemplate;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.authn.oidc.RestTemplateFactory;

public class IamJWKSetCacheService extends JWKSetCacheService {

  public static final String KEY_MATERIAL_ERROR_TEMPLATE =
      "Could not retrieve key material from {}";
  public static final Logger LOG = LoggerFactory.getLogger(IamJWKSetCacheService.class);

  private LoadingCache<String, JWTSigningAndValidationService> validators;
  private LoadingCache<String, JWTEncryptionAndDecryptionService> encrypters;

  public IamJWKSetCacheService(RestTemplateFactory rtf, int maxCacheSize, int expirationTime,
      TimeUnit timeUnit) {

    this.validators = CacheBuilder.newBuilder()
      .expireAfterWrite(expirationTime, timeUnit)
      .maximumSize(maxCacheSize)
      .build(new JWKSetVerifierFetcher(rtf));

    this.encrypters = CacheBuilder.newBuilder()
      .expireAfterWrite(expirationTime, timeUnit)
      .maximumSize(maxCacheSize)
      .build(new JWKSetEncryptorFetcher(rtf));
  }


  @Override
  public JWTSigningAndValidationService getValidator(String jwksUri) {

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
  public JWTEncryptionAndDecryptionService getEncrypter(String jwksUri) {
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

  public static class JWKSetEncryptorFetcher
      extends CacheLoader<String, JWTEncryptionAndDecryptionService> {

    final RestTemplateFactory rtf;

    public JWKSetEncryptorFetcher(RestTemplateFactory rtf) {
      this.rtf = rtf;
    }

    @Override
    public JWTEncryptionAndDecryptionService load(String key) throws Exception {
      
      RestTemplate rt = rtf.newRestTemplate();
      
      String jsonString = rt.getForObject(key, String.class);
      JWKSet jwkSet = JWKSet.parse(jsonString);

      JWKSetKeyStore keyStore = new JWKSetKeyStore(jwkSet);

      return new IamJWTEncryptionService(keyStore);
    }
  }

  public static class JWKSetVerifierFetcher
      extends CacheLoader<String, JWTSigningAndValidationService> {

    final RestTemplateFactory rtf;

    public JWKSetVerifierFetcher(RestTemplateFactory rtf) {
      this.rtf = rtf;
    }

    @Override
    public JWTSigningAndValidationService load(String key) throws Exception {
      
      RestTemplate rt = rtf.newRestTemplate();
      
      String jsonString = rt.getForObject(key, String.class);
      JWKSet jwkSet = JWKSet.parse(jsonString);

      JWKSetKeyStore keyStore = new JWKSetKeyStore(jwkSet);

      return new IamJWTSigningService(keyStore);
    }
  }
}
