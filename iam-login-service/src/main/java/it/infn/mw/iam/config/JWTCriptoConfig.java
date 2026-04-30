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
package it.infn.mw.iam.config;

import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

import it.infn.mw.iam.config.error.IAMJWTKeystoreError;
import it.infn.mw.iam.core.jwk.IamJWTEncryptionService;
import it.infn.mw.iam.core.jwk.IamJWTSigningService;
import it.infn.mw.iam.core.jwk.JwkKeyStore;
import it.infn.mw.iam.util.JwkKeyStoreLoader;

@Configuration
public class JWTCriptoConfig {

  public static final Logger LOG = LoggerFactory.getLogger(JWTCriptoConfig.class);

  @Bean
  JwkKeyStoreLoader loader(ResourceLoader resourceLoader) {
    return new JwkKeyStoreLoader(resourceLoader);
  }

  @Bean(name = "defaultKeyStore")
  JwkKeyStore defaultKeyStore(JwkKeyStoreLoader loader, IamProperties iamProperties) {
    String location = iamProperties.getJwk().getKeystoreLocation();
    LOG.info("Loading JWT keystore from: {}", location);
    return loader.load(location);
  }

  @Bean(name = "defaultsignerService")
  JWTSigningAndValidationService defaultSignerService(JwkKeyStore keystore,
      IamProperties iamProperties) {
    try {

      IamJWTSigningService signerService =
          new IamJWTSigningService(keystore, iamProperties.getJwk());

      LOG.info("Default JWK key id: {}", iamProperties.getJwk().getDefaultKeyId());
      LOG.info("Default JWS algorithm: {}", iamProperties.getJwk().getDefaultJwsAlgorithm());

      return signerService;
    } catch (Exception e) {
      throw new IAMJWTKeystoreError("Error creating JWT signing and validation service", e);
    }
  }

  @Bean(name = "defaultEncryptionService")
  JWTEncryptionAndDecryptionService defaultEncryptionService(JwkKeyStore keystore,
      IamProperties iamProperties) {

    try {

      IamJWTEncryptionService encryptionService =
          new IamJWTEncryptionService(keystore, iamProperties);

      LOG.info("Default JWE key encrypt key id: {}",
          iamProperties.getJwk().getDefaultJweEncryptKeyId());
      LOG.info("Default JWE key decrypt key id: {}",
          iamProperties.getJwk().getDefaultJweDecryptKeyId());
      LOG.info("Default JWE algorithm: {}", iamProperties.getJwk().getDefaultJweAlgorithm());

      return encryptionService;
    } catch (Exception e) {
      throw new IAMJWTKeystoreError("Error creating JWT encryption/decription service", e);
    }
  }

}
