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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.Maps.newHashMap;
import static com.google.common.collect.Sets.newHashSet;
import static it.infn.mw.iam.core.jwk.JWKUtils.buildDecrypter;
import static it.infn.mw.iam.core.jwk.JWKUtils.buildEncrypter;
import static java.util.Objects.isNull;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.logging.log4j.util.Strings;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWEProvider;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.JWK;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.error.NoSuchKeyError;
import it.infn.mw.iam.core.error.StartupError;


public class IamJWTEncryptionService implements JWTEncryptionAndDecryptionService {

  private static final Logger LOG = LoggerFactory.getLogger(IamJWTEncryptionService.class);

  private static final String KEY_INIT_ERROR_MSG = "Error initializing keys";

  private static final String ENCRYPTION_ERROR_MSG = "JWT encryption error: {}";
  private static final String DECRYPTION_ERROR_MSG = "JWT decryption error: {}";
  private static final String NO_PRIVATE_KEY_MSG = "No private key found for key id {}";

  private final Map<String, JWEEncrypter> encrypters = newHashMap();
  private final Map<String, JWEDecrypter> decrypters = newHashMap();

  private final Map<String, JWK> allPublicKeys = newHashMap();
  private final Set<JWEAlgorithm> allAlgorithms = newHashSet();
  private final Set<EncryptionMethod> allEncryptionMethods = newHashSet();

  private final String defaultJweEncryptKeyId;
  private final String defaultJweDecryptKeyId;

  private final JWKSetKeyStore keystore;

  public IamJWTEncryptionService(IamProperties properties, JWKSetKeyStore keyStore) {
    checkNotNull(keyStore, "Please provide a keystore");
    checkNotNull(properties, "Please provide properties");
    this.keystore = keyStore;
    this.defaultJweEncryptKeyId = properties.getJwk().getDefaultJweEncryptKeyId();
    this.defaultJweDecryptKeyId = properties.getJwk().getDefaultJweDecryptKeyId();
    initializeEncryptersAndDecrypters();
  }

  public IamJWTEncryptionService(JWKSetKeyStore keyStore, String defaultKeyId) {
    checkNotNull(keyStore, "Please provide a keystore");
    checkArgument(!keyStore.getKeys().isEmpty(), "Please provide a non-empty keystore");
    this.keystore = keyStore;

    if (!isNull(defaultKeyId)) {
      this.defaultJweDecryptKeyId = defaultKeyId;
      this.defaultJweEncryptKeyId = defaultKeyId;
    } else {
      JWK firstKey = keystore.getKeys().stream().findFirst().orElseThrow();
      this.defaultJweDecryptKeyId = firstKey.getKeyID();
      this.defaultJweEncryptKeyId = firstKey.getKeyID();
    }

    initializeEncryptersAndDecrypters();

  }

  public IamJWTEncryptionService(JWKSetKeyStore keyStore) {
    this(keyStore, null);
  }


  @Override
  public void encryptJwt(JWEObject jwt) {

    JWEEncrypter encrypter =
        Optional.ofNullable(encrypters.get(defaultJweEncryptKeyId))
          .orElseThrow(NoSuchKeyError.forKeyId(defaultJweEncryptKeyId));

    try {
      jwt.encrypt(encrypter);
    } catch (JOSEException e) {
      LOG.error(ENCRYPTION_ERROR_MSG, e.getMessage());
    }

  }

  @Override
  public void decryptJwt(JWEObject jwt) {
    JWEDecrypter decrypter = Optional.ofNullable(decrypters.get(defaultJweDecryptKeyId))
      .orElseThrow(NoSuchKeyError.forKeyId(defaultJweDecryptKeyId));

    try {
      jwt.decrypt(decrypter);
    } catch (JOSEException e) {
      LOG.error(DECRYPTION_ERROR_MSG, e.getMessage());
    }

  }

  @Override
  public Map<String, JWK> getAllPublicKeys() {
    return allPublicKeys;
  }

  @Override
  public Collection<JWEAlgorithm> getAllEncryptionAlgsSupported() {
    return allAlgorithms;
  }

  @Override
  public Collection<EncryptionMethod> getAllEncryptionEncsSupported() {
    return allEncryptionMethods;
  }


  private void registerProvider(JWEProvider provider) {
    allAlgorithms.addAll(provider.supportedJWEAlgorithms());
    allEncryptionMethods.addAll(provider.supportedEncryptionMethods());
  }

  private void registerEncrypter(JWK jwk, JWEEncrypter encrypter) {
    registerProvider(encrypter);
    encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
    encrypters.put(jwk.getKeyID(), encrypter);
  }

  private void registerDecrypter(JWK jwk, JWEDecrypter decrypter) {
    registerProvider(decrypter);
    decrypters.put(jwk.getKeyID(), decrypter);
  }


  protected void buildEncrypterDecrypter(JWK jwk) {
    try {

      Optional.ofNullable(jwk.toPublicJWK()).ifPresent(k -> allPublicKeys.put(k.getKeyID(), k));
      buildEncrypter(jwk).ifPresent(e -> registerEncrypter(jwk, e));

      if (jwk.isPrivate()) {
        buildDecrypter(jwk).ifPresent(d -> registerDecrypter(jwk, d));
      } else {
        LOG.info(NO_PRIVATE_KEY_MSG, jwk.getKeyID());
      }

    } catch (JOSEException e) {
      throw new StartupError(KEY_INIT_ERROR_MSG, e);
    }
  }

  protected void initializeEncryptersAndDecrypters() {
    keystore.getKeys()
      .stream()
      .filter(k -> Strings.isNotBlank(k.getKeyID()))
      .forEach(this::buildEncrypterDecrypter);
  }
}
