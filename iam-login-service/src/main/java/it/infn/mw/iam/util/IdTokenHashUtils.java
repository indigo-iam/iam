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
package it.infn.mw.iam.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;

import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;

public class IdTokenHashUtils {

  private static final Set<JWSAlgorithm> SHA_256_ALGORITHMS =
      Set.of(JWSAlgorithm.RS256, JWSAlgorithm.HS256, JWSAlgorithm.ES256, JWSAlgorithm.PS256);

  private static final Set<JWSAlgorithm> SHA_384_ALGORITHMS =
      Set.of(JWSAlgorithm.RS384, JWSAlgorithm.HS384, JWSAlgorithm.ES384, JWSAlgorithm.PS384);

  private static final Set<JWSAlgorithm> SHA_512_ALGORITHMS =
      Set.of(JWSAlgorithm.RS512, JWSAlgorithm.HS512, JWSAlgorithm.ES512, JWSAlgorithm.PS512);

  private static final Logger logger = LoggerFactory.getLogger(IdTokenHashUtils.class);

  private IdTokenHashUtils() {}

  /**
   * Compute the SHA hash of an authorization code
   *
   * @param signingAlg
   * @param code
   * @return
   */
  public static Base64URL getCodeHash(JWSAlgorithm signingAlg, String code) {
    return getHash(signingAlg, code.getBytes());
  }

  /**
   * Compute the SHA hash of a token
   *
   * @param signingAlg
   * @param token
   * @return
   */
  public static Base64URL getAccessTokenHash(JWSAlgorithm signingAlg,
      OAuth2AccessTokenEntity token) {

    byte[] tokenBytes = token.getJwt().serialize().getBytes();

    return getHash(signingAlg, tokenBytes);

  }

  public static Base64URL getHash(JWSAlgorithm signingAlg, byte[] bytes) {

    String hashAlg = null;
    if (SHA_256_ALGORITHMS.contains(signingAlg)) {
      hashAlg = "SHA-256";
    } else if (SHA_384_ALGORITHMS.contains(signingAlg)) {
      hashAlg = "SHA-384";
    } else if (SHA_512_ALGORITHMS.contains(signingAlg)) {
      hashAlg = "SHA-512";
    } else {
      return null;
    }

    try {

      MessageDigest hasher = MessageDigest.getInstance(hashAlg);
      hasher.reset();
      hasher.update(bytes);

      byte[] hashBytes = hasher.digest();
      byte[] hashBytesLeftHalf = Arrays.copyOf(hashBytes, hashBytes.length / 2);
      return Base64URL.encode(hashBytesLeftHalf);

    } catch (NoSuchAlgorithmException e) {

      logger.error("No such algorithm error: ", e);
      return null;
    }
  }

}
