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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;

import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;

public class IdTokenHashUtils {

  private static final Logger logger = LoggerFactory.getLogger(IdTokenHashUtils.class);

  public static Base64URL getCodeHash(JWSAlgorithm signingAlg, String code) {
    return getHash(signingAlg, code.getBytes());
  }

  public static Base64URL getAccessTokenHash(JWSAlgorithm signingAlg,
      OAuth2AccessTokenEntity token) {

    byte[] tokenBytes = token.getJwt().serialize().getBytes();

    return getHash(signingAlg, tokenBytes);

  }

  public static Base64URL getHash(JWSAlgorithm signingAlg, byte[] bytes) {

    String hashAlg = null;

    if (signingAlg.equals(JWSAlgorithm.HS256) || signingAlg.equals(JWSAlgorithm.ES256)
        || signingAlg.equals(JWSAlgorithm.RS256) || signingAlg.equals(JWSAlgorithm.PS256)) {
      hashAlg = "SHA-256";
    }

    else if (signingAlg.equals(JWSAlgorithm.ES384) || signingAlg.equals(JWSAlgorithm.HS384)
        || signingAlg.equals(JWSAlgorithm.RS384) || signingAlg.equals(JWSAlgorithm.PS384)) {
      hashAlg = "SHA-384";
    }

    else if (signingAlg.equals(JWSAlgorithm.ES512) || signingAlg.equals(JWSAlgorithm.HS512)
        || signingAlg.equals(JWSAlgorithm.RS512) || signingAlg.equals(JWSAlgorithm.PS512)) {
      hashAlg = "SHA-512";
    }

    if (hashAlg != null) {

      try {
        MessageDigest hasher = MessageDigest.getInstance(hashAlg);
        hasher.reset();
        hasher.update(bytes);

        byte[] hashBytes = hasher.digest();
        byte[] hashBytesLeftHalf = Arrays.copyOf(hashBytes, hashBytes.length / 2);
        Base64URL encodedHash = Base64URL.encode(hashBytesLeftHalf);

        return encodedHash;

      } catch (NoSuchAlgorithmException e) {

        logger.error("No such algorithm error: ", e);
      }
    }

    return null;
  }

}
