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
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"saml.login-shortcuts[0].name=test",
    "saml.login-shortcuts[0].entityId=https://idptestbed/idp/shibboleth",
    "saml.login-shortcuts[0].loginButton.text=Sign in with Test IDP"
})
@Transactional
@WithAnonymousUser
public class LoginShortcutsTests {
  
  @Autowired
  private MockMvc mvc;

  @Test
  public void getLoginShortcutsConfiguration() throws Exception {
    
    mvc.perform(get("/iam/config/saml/shortcuts"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[0].name", is("test")))
      .andExpect(jsonPath("$[0].entityId", is("https://idptestbed/idp/shibboleth")))
      .andExpect(jsonPath("$[0].loginButton.text", is("Sign in with Test IDP")));    
  }
}
