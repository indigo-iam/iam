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
package it.infn.mw.iam.util.ssh;

import java.security.MessageDigest;
import java.util.Base64;

import org.apache.commons.codec.digest.MessageDigestAlgorithms;

public class RSAPublicKeyUtils {

  private RSAPublicKeyUtils() {}
  

  public static String getSHA256Fingerprint(String key) {

    return buildSHA256Fingerprint(key);
  }

  private static String buildSHA256Fingerprint(String keyVal) throws InvalidSshKeyException {
    
    final String[] keyParts = keyVal.split("\\s");
    String encodedKey;

    if (keyParts.length == 0) {
      encodedKey = keyVal;
    } else if (keyParts.length == 1) {
      encodedKey = keyParts[0];
    } else {
      encodedKey = keyParts[1];
    }

    String fingerprint = null;

    try {

      byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
      byte[] digest = MessageDigest.getInstance(MessageDigestAlgorithms.SHA_256).digest(decodedKey);
      fingerprint = Base64.getEncoder().encodeToString(digest);

    } catch (Exception e) {

      throw new InvalidSshKeyException(
          "Error during fingerprint generation: RSA key is not base64 encoded", e);
    }

    return fingerprint;
  }
}
