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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.core.io.DefaultResourceLoader;

import it.infn.mw.iam.config.error.IAMJWTKeystoreError;
import it.infn.mw.iam.util.JWKKeystoreLoader;

@RunWith(JUnit4.class)
public class JWKLoaderErrorTests {

  DefaultResourceLoader rl = new DefaultResourceLoader();

  @Test(expected = IAMJWTKeystoreError.class)
  public void testStartupError() {
    JWKKeystoreLoader kl = new JWKKeystoreLoader(rl);

    kl.loadKeystoreFromLocation("/does/not/exists");
  }

}
