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
package it.infn.mw.iam.test.ext_authn.saml;

import static org.hamcrest.CoreMatchers.is;
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
@TestPropertySource(properties = {"saml.wayf-login-button.text=Sign in with EduGAIN",
    "saml.wayf-login-button.image.url=https://example.org/test.png"
})
@WithAnonymousUser
public class WayfLoginButtonTests {

  @Autowired
  private MockMvc mvc;
  
  @Test
  public void getWayfLoginButtonConfiguration() throws Exception {
    
    mvc.perform(get("/iam/config/saml/wayf-login-button"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.text", is("Sign in with EduGAIN")))
      .andExpect(jsonPath("$.image.url", is("https://example.org/test.png")))
      .andExpect(jsonPath("$.image.size", is("SMALL")))
      .andExpect(jsonPath("$.visible", is(true)));
  }

}
