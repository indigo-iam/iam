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
package it.infn.mw.iam.test.api.config;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithAnonymousUser
//@formatter:off
@TestPropertySource(properties = {
    "iam.privacy-policy.url=https://policy.example",
    "iam.privacy-policy.text=Privacy Statement"
})
//@formatter:on
public class PrivacyPolicyConfigurationTests {

  private static final String ENDPOINT = "/iam/config/privacy-policy";


  @Autowired
  private MockMvc mvc;

  @Test
  public void testPrivacyPolicy() throws Exception {

    mvc.perform(get((ENDPOINT)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.url").value("https://policy.example"))
      .andExpect(jsonPath("$.text").value("Privacy Statement"));

  }
}
