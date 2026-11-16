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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import it.infn.mw.iam.core.user.validation.BCryptLengthValidator;

class BCryptLengthValidatorTests {

  private final BCryptLengthValidator validator = new BCryptLengthValidator();

  @Test
  void leavesRequiredValueValidationToOtherConstraints() {
    assertTrue(validator.isValid(null, null));
    assertTrue(validator.isValid("", null));
  }

  @Test
  void validatesUtf8BoundaryForOneTwoThreeAndFourByteCharacters() {
    for (String character : new String[] {"a", "é", "€", "😀"}) {
      int bytes = character.getBytes(StandardCharsets.UTF_8).length;
      String boundary = character.repeat(72 / bytes);
      assertTrue(validator.isValid(boundary, null));
      assertFalse(validator.isValid(boundary + "a", null));
    }
  }
}
