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


package it.infn.mw.iam.test.actuator;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = {"iam.external-connectivity-probe.enabled=true"})
@AutoConfigureMockMvc
class ExternalServiceProbeActuatorTests extends ActuatorTestSupport {

  @Autowired
  MockMvc mvc;

  @Test
  void testUnauthenticatedHealthEndpointRequest() throws Exception {

    mvc.perform(get(HEALTH_ENDPOINT))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status").value(STATUS_UP))
      .andExpect(jsonPath("$.components.externalConnectivity.status").value(STATUS_UP));
  }

}
