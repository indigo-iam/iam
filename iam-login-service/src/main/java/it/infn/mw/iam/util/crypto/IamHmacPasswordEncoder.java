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
package it.infn.mw.iam.util.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.crypto.password.PasswordEncoder;

public class IamHmacPasswordEncoder implements PasswordEncoder {

  private final SecretKeySpec pepperKey;

  public IamHmacPasswordEncoder(String masterKey) {

    if (masterKey == null || masterKey.isBlank()) {
      throw new IllegalArgumentException(
          "Property 'iam.client.secret-encoder-key' must not be null or empty");
    }
    this.pepperKey = new SecretKeySpec(masterKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
  }

  @Override
  public String encode(CharSequence rawPassword) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(pepperKey);

      byte[] digest = mac.doFinal(rawPassword.toString().getBytes(StandardCharsets.UTF_8));

      return Base64.getEncoder().encodeToString(digest);

    } catch (Exception e) {
      throw new IllegalStateException("Unable to calculate HMAC", e);
    }
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {

    if (rawPassword == null || encodedPassword == null) {
      return false;
    }

    String calculated = encode(rawPassword);

    return MessageDigest.isEqual(calculated.getBytes(StandardCharsets.UTF_8),
        encodedPassword.getBytes(StandardCharsets.UTF_8));
  }
}
