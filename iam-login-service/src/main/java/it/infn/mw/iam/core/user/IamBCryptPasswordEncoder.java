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
package it.infn.mw.iam.core.user;

import java.nio.charset.StandardCharsets;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** BCrypt encoder that never silently accepts a password beyond its UTF-8 limit. */
public final class IamBCryptPasswordEncoder extends BCryptPasswordEncoder {

  public static final int MAX_PASSWORD_BYTES = 72;
  public static final String PASSWORD_TOO_LONG_MESSAGE =
      "The password must not exceed 72 bytes when encoded in UTF-8";

  public static boolean exceedsMaxLength(CharSequence password) {
    return password != null && (password.length() > MAX_PASSWORD_BYTES
        || password.toString().getBytes(StandardCharsets.UTF_8).length > MAX_PASSWORD_BYTES);
  }

  @Override
  public String encode(CharSequence rawPassword) {
    if (exceedsMaxLength(rawPassword)) {
      throw new IllegalArgumentException(PASSWORD_TOO_LONG_MESSAGE);
    }
    return super.encode(rawPassword);
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    return !exceedsMaxLength(rawPassword) && super.matches(rawPassword, encodedPassword);
  }
}
