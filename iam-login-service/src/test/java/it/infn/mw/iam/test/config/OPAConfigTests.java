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
package it.infn.mw.iam.test.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.scope.pdp.OpaScopePolicyEngine;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopePolicyEngine;

@SpringBootTest(classes = {IamLoginService.class})
@TestPropertySource(properties = {"iam.opa.enabled=true", "iam.opa.url=http://opa:8181"})
class OPAConfigTests {

  @Autowired
  private ScopePolicyEngine scopePolicyEngine;

  @Autowired
  private IamProperties properties;

  @Test
  void testUseOpaScopePolicyEngine() {

    assertInstanceOf(OpaScopePolicyEngine.class, scopePolicyEngine);

  }

  @Test
  void testCheckOpaProperties() {

    assertEquals(true, properties.getOpa().isEnabled());
    assertEquals("http://opa:8181", properties.getOpa().getUrl());

  }

}
