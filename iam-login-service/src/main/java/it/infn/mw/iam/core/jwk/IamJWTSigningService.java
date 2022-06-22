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
import static it.infn.mw.iam.core.jwk.JWKUtils.buildSigner;
import static it.infn.mw.iam.core.jwk.JWKUtils.buildVerifier;
import static java.lang.String.format;
import static java.util.Optional.ofNullable;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.logging.log4j.util.Strings;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.config.IamProperties.JWKProperties;
import it.infn.mw.iam.core.error.StartupError;


public class IamJWTSigningService implements JWTSigningAndValidationService {

  private static final Logger LOG = LoggerFactory.getLogger(IamJWTSigningService.class);

  private static final String SIGNER_NOT_FOUND_FOR_KEY_MSG = "Signer not found for key %s";
  private static final String SIGNER_NOT_FOUND_FOR_ALGO_MSG = "Signer not found for algorithm {}";
  private static final String SIGNATURE_ERROR_MSG = "Error signing JWT: {}";
  private static final String SIGNATURE_VERIFICATION_ERROR_MSG = "Error verifying signature: {}";
  private static final String VERIFIER_NOT_FOUND_MSG = "JWS verifier not found for key {}";
  private static final String KEY_INIT_ERROR_MSG = "Error initializing keys";

  private final JWKSetKeyStore keystore;

  private final Set<JWSAlgorithm> allAlgorithms = newHashSet();
  private Map<String, JWSSigner> signers = newHashMap();
  private Map<String, JWSVerifier> verifiers = newHashMap();
  private Map<String, JWK> allPublicKeys = newHashMap();

  private final JWSAlgorithm defaultAlgorithm;
  private final String defaultSignerKeyId;

  public IamJWTSigningService(JWKProperties properties, JWKSetKeyStore keystore) {
    checkNotNull(keystore, "null keystore");
    checkNotNull(properties, "null properties");

    checkArgument(!keystore.getKeys().isEmpty(),
        "empty keystore");
    this.keystore = keystore;

    this.defaultAlgorithm = JWSAlgorithm.parse(properties.getDefaultJwsAlgorithm());
    this.defaultSignerKeyId = properties.getDefaultKeyId();
    initializeSignersAndVerifiers();
  }

  public IamJWTSigningService(JWKSetKeyStore keystore) {
    this(keystore, null, null);
  }

  public IamJWTSigningService(JWKSetKeyStore keystore, String defaultKeyId,
      String defaultAlgorithm) {
    checkNotNull(keystore, "null keystore");
    checkArgument(!keystore.getKeys().isEmpty(), "Please provide a non-empty keystore");
    this.keystore = keystore;
    this.defaultAlgorithm =
        Optional.ofNullable(defaultAlgorithm).map(JWSAlgorithm::parse).orElse(null);
    this.defaultSignerKeyId = Optional.ofNullable(defaultKeyId)
      .orElse(keystore.getKeys().stream().findFirst().orElseThrow().getKeyID());
    initializeSignersAndVerifiers();
  }

  private void registerVerifier(JWK jwk, JWSVerifier verifier) {
    verifiers.put(jwk.getKeyID(), verifier);
    allAlgorithms.addAll(verifier.supportedJWSAlgorithms());
    allPublicKeys.put(jwk.getKeyID(), jwk.toPublicJWK());
  }

  private void registerSigner(JWK jwk, JWSSigner signer) {
    signers.put(jwk.getKeyID(), signer);
    allAlgorithms.addAll(signer.supportedJWSAlgorithms());
  }


  protected void buildSignerVerifier(JWK jwk) {
    try {
      if (jwk.isPrivate()) {
        buildSigner(jwk).ifPresent(s -> registerSigner(jwk, s));
      }

      buildVerifier(jwk).ifPresent(v -> registerVerifier(jwk, v));

    } catch (JOSEException e) {
      throw new StartupError(KEY_INIT_ERROR_MSG, e);
    }
  }

  protected void initializeSignersAndVerifiers() {
    keystore.getKeys()
      .stream()
      .filter(k -> Strings.isNotBlank(k.getKeyID()))
      .forEach(this::buildSignerVerifier);
  }

  @Override
  public Map<String, JWK> getAllPublicKeys() {
    return allPublicKeys;
  }

  @Override
  public boolean validateSignature(SignedJWT signedJwt) {

    Optional<JWSVerifier> verifier =
        Optional.ofNullable(verifiers.get(signedJwt.getHeader().getKeyID()));

    if (verifier.isPresent()) {
      try {
        return signedJwt.verify(verifier.get());
      } catch (JOSEException e) {
        LOG.warn(SIGNATURE_VERIFICATION_ERROR_MSG, e.getMessage(), e);
      }
    } else {
      LOG.warn(VERIFIER_NOT_FOUND_MSG, signedJwt.getHeader().getKeyID());
    }

    return false;
  }

  private void signJwt(JWSSigner signer, SignedJWT jwt) {
    try {
      jwt.sign(signer);
    } catch (JOSEException e) {
      LOG.error(SIGNATURE_ERROR_MSG, e.getMessage(), e);
    }
  }

  private JWSSigner resolveSigner(SignedJWT jwt) {

    final String key = ofNullable(jwt.getHeader().getKeyID()).orElse(defaultSignerKeyId);
    return ofNullable(signers.get(key))
      .orElseThrow(() -> new IllegalArgumentException(
          format(SIGNER_NOT_FOUND_FOR_KEY_MSG, jwt.getHeader().getKeyID())));
  }

  @Override
  public void signJwt(SignedJWT jwt) {
    signJwt(resolveSigner(jwt), jwt);
  }

  @Override
  public JWSAlgorithm getDefaultSigningAlgorithm() {
    return defaultAlgorithm;
  }

  @Override
  public Collection<JWSAlgorithm> getAllSigningAlgsSupported() {
    return allAlgorithms;
  }

  @Override
  public void signJwt(SignedJWT jwt, JWSAlgorithm alg) {

    Optional<JWSSigner> signer =
        signers.values().stream().filter(s -> s.supportedJWSAlgorithms().contains(alg)).findFirst();

    signer.ifPresentOrElse(s -> signJwt(s, jwt),
        () -> LOG.error(SIGNER_NOT_FOUND_FOR_ALGO_MSG, alg.getName()));
  }

  @Override
  public String getDefaultSignerKeyId() {
    return defaultSignerKeyId;
  }

}
