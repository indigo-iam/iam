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

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import it.infn.mw.iam.core.user.IamBCryptPasswordEncoder;

class IamBCryptPasswordEncoderTests {
  private final IamBCryptPasswordEncoder encoder = new IamBCryptPasswordEncoder();

  @Test
  void accepts72BytesAndRejectsAdditionalSuffix() {
    String password = "a".repeat(72);
    String hash = encoder.encode(password);
    assertTrue(encoder.matches(password, hash));
    assertFalse(encoder.matches(password + "b", hash));
    assertThrows(IllegalArgumentException.class, () -> encoder.encode(password + "b"));
  }

  @Test
  void measuresUtf8Bytes() {
    String password = "é".repeat(36);
    String hash = encoder.encode(password);
    assertTrue(encoder.matches(password, hash));
    assertFalse(encoder.matches(password + "é", hash));
    assertThrows(IllegalArgumentException.class, () -> encoder.encode(password + "é"));
  }

  @Test
  void supportsSupplementaryUnicodeCharacters() {
    String password = "😀".repeat(18);
    String hash = encoder.encode(password);
    assertTrue(encoder.matches(password, hash));
    assertFalse(encoder.matches(password + "a", hash));
  }

  @Test
  void preservesExistingHashesAndRejectsWrongPassword() {
    String hash = new BCryptPasswordEncoder().encode("Existing-password1!");
    assertTrue(encoder.matches("Existing-password1!", hash));
    assertFalse(encoder.matches("wrong-password", hash));
  }

  @Test
  void doesNotTrimOrNormalizePasswords() {
    String hash = encoder.encode(" secret ");
    assertTrue(encoder.matches(" secret ", hash));
    assertFalse(encoder.matches("secret", hash));
  }

  @Test
  void preservesNullRejectionAndNeverIncludesPasswordInError() {
    assertThrows(IllegalArgumentException.class, () -> encoder.encode(null));
    assertThrows(IllegalArgumentException.class, () -> encoder.matches(null, "hash"));
    String password = "sensitive".repeat(20);
    var error = assertThrows(IllegalArgumentException.class, () -> encoder.encode(password));
    assertEquals(IamBCryptPasswordEncoder.PASSWORD_TOO_LONG_MESSAGE, error.getMessage());
  }
}
