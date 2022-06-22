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
import static com.nimbusds.jose.jwk.gen.RSAKeyGenerator.MIN_KEY_SIZE_BITS;

import java.security.PrivateKey;
import java.util.Collections;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSSignerOption;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.impl.RSAKeyUtils;
import com.nimbusds.jose.crypto.opts.AllowWeakRSAKey;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

public class JWKUtils {

  private static final Logger LOG = LoggerFactory.getLogger(JWKUtils.class);

  public static final int MIN_SIZE_KEY_BITS = 2048;

  public static final String INVALID_KEY_SIZE_MSG =
      "Size in bits for key {} is smaller than the recommended minimum: {} < {}.";

  public static final String UNSUPPORTED_KEY_TYPE_MSG = "Unsupported key type {} for key id {}";

  private JWKUtils() {
    // prevent instantiation
  }

  public static Optional<JWSVerifier> buildVerifier(JWK jwk) throws JOSEException {
    final JWSVerifier verifier;

    if (jwk instanceof RSAKey) {
      verifier = new RSASSAVerifier((RSAKey) jwk);
    } else if (jwk instanceof ECKey) {
      verifier = new ECDSAVerifier((ECKey) jwk);
    } else if (jwk instanceof OctetSequenceKey) {
      verifier = new MACVerifier((OctetSequenceKey) jwk);
    } else {
      LOG.warn(UNSUPPORTED_KEY_TYPE_MSG, jwk.getClass().getName(), jwk.getKeyID());
      verifier = null;
    }
    return Optional.ofNullable(verifier);
  }

  public static Optional<JWSSigner> buildSigner(JWK jwk) throws JOSEException {
    checkArgument(jwk.isPrivate(), "buildSigner requires a private jwk");
    final JWSSigner signer;

    if (jwk instanceof RSAKey) {

      RSAKey rsaJwk = (RSAKey) jwk;

      PrivateKey privateKey = RSAKeyUtils.toRSAPrivateKey(rsaJwk);
      int keyBitLength = RSAKeyUtils.keyBitLength(privateKey);
      
      if (keyBitLength > 0 && keyBitLength < MIN_KEY_SIZE_BITS) {
        LOG.warn(INVALID_KEY_SIZE_MSG, jwk.getKeyID(), keyBitLength, MIN_SIZE_KEY_BITS);
      }

      signer = new RSASSASigner(privateKey,
          Collections.singleton((JWSSignerOption) AllowWeakRSAKey.getInstance()));
    } else if (jwk instanceof ECKey) {
      signer = new ECDSASigner((ECKey) jwk);
    } else if (jwk instanceof OctetSequenceKey) {
      signer = new MACSigner((OctetSequenceKey) jwk);
    } else {
      LOG.warn(UNSUPPORTED_KEY_TYPE_MSG, jwk.getClass().getName(), jwk.getKeyID());
      signer = null;
    }

    return Optional.ofNullable(signer);
  }

  public static Optional<JWEEncrypter> buildEncrypter(JWK jwk) throws JOSEException {

    final JWEEncrypter encrypter;

    if (jwk instanceof RSAKey) {
      encrypter = new RSAEncrypter((RSAKey) jwk);
    } else if (jwk instanceof ECKey) {
      encrypter = new ECDHEncrypter((ECKey) jwk);
    } else if (jwk instanceof OctetSequenceKey) {
      encrypter = new DirectEncrypter((OctetSequenceKey) jwk);
    } else {
      encrypter = null;
      LOG.warn(UNSUPPORTED_KEY_TYPE_MSG, jwk.getClass().getName(), jwk.getKeyID());
    }

    return Optional.ofNullable(encrypter);
  }

  public static Optional<JWEDecrypter> buildDecrypter(JWK jwk) throws JOSEException {
    final JWEDecrypter decrypter;

    if (jwk instanceof RSAKey) {
      decrypter = new RSADecrypter(RSAKeyUtils.toRSAPrivateKey(jwk.toRSAKey()), null, true);
    } else if (jwk instanceof ECKey) {
      decrypter = new ECDHDecrypter((ECKey) jwk);
    } else if (jwk instanceof OctetSequenceKey) {
      decrypter = new DirectDecrypter((OctetSequenceKey) jwk);
    } else {
      decrypter = null;
      LOG.warn(UNSUPPORTED_KEY_TYPE_MSG, jwk.getClass().getName(), jwk.getKeyID());
    }

    return Optional.ofNullable(decrypter);
  }
}
