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
package it.infn.mw.iam.test.startup;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.Test;
import org.springframework.beans.BeansException;

import it.infn.mw.iam.IamLoginService;

public class ApplicationStartupValidationTests {

  @Test(expected = BeansException.class)
  public void testFailureOnStatupDueToWrongEnum() {

    IamLoginService.main(new String[] {"--iam.jwt-profile.default-profile=pippo"});
  }

  @Test
  public void testSuccessStatup() {

    assertDoesNotThrow(() -> IamLoginService.main(new String[] {}));
  }

}
