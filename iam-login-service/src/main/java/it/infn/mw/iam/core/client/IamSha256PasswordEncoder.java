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
package it.infn.mw.iam.core.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.core.Sha256Encoder;

public class IamSha256PasswordEncoder implements PasswordEncoder {

  @Override
  public String encode(CharSequence rawPassword) {

    if (rawPassword == null) {
      return null;
    }

    return Sha256Encoder.encode(rawPassword.toString());
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {

    if (rawPassword == null || encodedPassword == null) {
      return false;
    }

    return MessageDigest.isEqual(encode(rawPassword).getBytes(StandardCharsets.UTF_8),
        encodedPassword.getBytes(StandardCharsets.UTF_8));
  }
}
