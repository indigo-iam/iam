/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2026
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

import static it.infn.mw.iam.util.LogUtils.sanitizeForLogging;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class LogUtilsTests {

  static Stream<Arguments> logValues() {
    return Stream.of(Arguments.of("alice", "alice"), Arguments.of("", ""),
        Arguments.of("Alice Rossi_123", "Alice Rossi_123"),
        Arguments.of("caf\u00e9 \u4e2d\u6587", "caf\u00e9 \u4e2d\u6587"),
        Arguments.of("alice\nadmin", "alice_admin"), Arguments.of("alice\radmin", "alice_admin"),
        Arguments.of("alice\r\nadmin", "alice__admin"), Arguments.of("alice\tadmin", "alice_admin"),
        Arguments.of("alice\u0000admin", "alice_admin"),
        Arguments.of("alice\u001b[31m", "alice_[31m"),
        Arguments.of("alice\u007fadmin", "alice_admin"),
        Arguments.of("alice\u0085admin", "alice_admin"),
        Arguments.of("alice\u2028admin", "alice_admin"),
        Arguments.of("alice\u2029admin", "alice_admin"));
  }

  @ParameterizedTest
  @MethodSource("logValues")
  void testSanitizeForLogging(String input, String expected) {
    assertEquals(expected, sanitizeForLogging(input));
    assertEquals(expected, sanitizeForLogging(expected));
  }

  @Test
  void testNullValue() {
    assertNull(sanitizeForLogging(null));
  }
}
