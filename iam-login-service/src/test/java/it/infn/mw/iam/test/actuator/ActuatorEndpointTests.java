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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class ActuatorEndpointTests extends ActuatorTestSupport {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamProperties iamProperties;

  @Test
  public void testUnauthenticatedHealthEndpointRequest() throws Exception {

    mvc.perform(get(HEALTH_ENDPOINT))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(STATUS_UP)))
      .andExpect(jsonPath("$.components.db.status", equalTo(STATUS_UP)))
      .andExpect(jsonPath("$.components.db.detail").doesNotExist())
      .andExpect(jsonPath("$.components.diskSpace.status", equalTo(STATUS_UP)))
      .andExpect(jsonPath("$.components.ping.status", equalTo(STATUS_UP)))
      .andExpect(jsonPath("$.components.diskSpace.detail").doesNotExist());

  }

  @Test
  public void testUnauthenticatedInfoEndpointRequest() throws Exception {

    mvc.perform(get(INFO_ENDPOINT))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.git", notNullValue()))
      .andExpect(jsonPath("$.build", notNullValue()))
      .andExpect(jsonPath("$.build.name", equalTo("IAM Login Service")));
  }

  @Test
  public void testAuthenticatedHealthEndpointShowDetails() throws Exception {
    mvc
      .perform(get(HEALTH_ENDPOINT).with(httpBasic(iamProperties.getActuatorUser().getUsername(),
          iamProperties.getActuatorUser().getPassword())))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(STATUS_UP)))
      .andExpect(jsonPath("$.components.diskSpace.status", equalTo(STATUS_UP)))
      .andExpect(jsonPath("$.components.diskSpace.details").exists());
  }

}
