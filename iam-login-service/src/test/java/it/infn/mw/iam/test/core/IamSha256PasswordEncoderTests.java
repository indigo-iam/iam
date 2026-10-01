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
package it.infn.mw.iam.test.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import it.infn.mw.iam.core.Sha256Encoder;
import it.infn.mw.iam.core.client.IamSha256PasswordEncoder;

class IamSha256PasswordEncoderTests {

  private final IamSha256PasswordEncoder encoder = new IamSha256PasswordEncoder();

  @Test
  void testEncodeReturnsNullWhenPasswordIsNull() {

    assertNull(encoder.encode(null));
  }

  @Test
  void testEncodeReturnsSha256Hash() {

    String encodedPassword = encoder.encode("password");

    assertEquals(Sha256Encoder.encode("password"), encodedPassword);
  }

  @Test
  void testEncodeReturnsDifferentHashForDifferentPasswords() {

    String first = encoder.encode("password");
    String second = encoder.encode("new-password");

    assertNotEquals(first, second);
  }

  @Test
  void testMatchesReturnsTrueWhenPasswordMatches() {

    String encodedPassword = encoder.encode("password");

    assertTrue(encoder.matches("password", encodedPassword));
  }

  @Test
  void testMatchesReturnsFalseWhenPasswordDoesNotMatch() {
    String encodedPassword = encoder.encode("password");

    assertFalse(encoder.matches("wrong-password", encodedPassword));
  }

  @Test
  void testMatchesReturnsFalseWhenRawPasswordIsNull() {

    assertFalse(encoder.matches(null, "some-hash"));
  }

  @Test
  void testMatchesReturnsFalseWhenEncodedPasswordIsNull() {
    assertFalse(encoder.matches("password", null));
  }

  @Test
  void testMatchesReturnsFalseWhenBothPasswordsAreNull() {

    assertFalse(encoder.matches(null, null));
  }

  @Test
  void testMatchesReturnsFalseWhenEncodedPasswordIsInvalid() {

    assertFalse(encoder.matches("password", "invalid-hash"));
  }

  @Test
  void testMatchesOnEmptyPassword() {

    String encodedPassword = encoder.encode("");

    assertTrue(encoder.matches("", encodedPassword));
    assertFalse(encoder.matches("password", encodedPassword));
  }
}
