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

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * A simple util to quickly get a password bcrypt-encoded
 *
 */
public class IamClientSecretEncoder implements PasswordEncoder {

  final int DEFAULT_ROUND = 12;

  BCryptPasswordEncoder bcryptEncoder = new BCryptPasswordEncoder(DEFAULT_ROUND);

  @Override
  public String encode(CharSequence rawPassword) {
    if (rawPassword.isEmpty()) {
      return rawPassword.toString();
    }
    return bcryptEncoder.encode(rawPassword);
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    if (rawPassword == null) {
      throw new IllegalArgumentException("rawPassword cannot be null");
    }
    if (encodedPassword == null) {
      throw new IllegalArgumentException("encodedPassword cannot be null");
    }
    if (rawPassword.isEmpty() && encodedPassword.isEmpty()) {
      return true;
    }
    return bcryptEncoder.matches(rawPassword, encodedPassword);
  }

}
