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
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.beans.BeansException;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

import it.infn.mw.iam.IamLoginService;

class ApplicationStartupValidationTests {

  @Test
  void testFailureOnStatupDueToWrongEnum() {

    assertThrows(BeansException.class, () -> IamLoginService.main(new String[] {
        "--iam.jwt-profile.default-profile=pippo"}));
  }

  @Test
  void testSuccessStatup() {

    // IamLoginService.main() does not return the context: start it here, so that it can be closed
    // and does not stay in memory for the rest of the test run
    ConfigurableApplicationContext context =
        assertDoesNotThrow(() -> SpringApplication.run(IamLoginService.class));
    context.close();
  }

}
