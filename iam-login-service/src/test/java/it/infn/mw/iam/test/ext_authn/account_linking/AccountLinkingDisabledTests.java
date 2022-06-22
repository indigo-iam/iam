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
package it.infn.mw.iam.test.ext_authn.account_linking;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(properties = {"iam.account-linking.enable=false"})
public class AccountLinkingDisabledTests {

  @Autowired
  private MockMvc mvc;

  @Test
  @WithMockUser(username = "test")
  public void accountLinkingDisabledWorkAsExpected() throws Throwable {

    mvc.perform(post("/iam/account-linking/X509").with(csrf().asHeader()))
      .andExpect(status().isForbidden());

    mvc.perform(delete("/iam/account-linking/X509")
      .param("certificateSubject", "certificateSubject").with(csrf().asHeader()))
      .andExpect(status().isForbidden());

    mvc.perform(post("/iam/account-linking/OIDC").with(csrf().asHeader()))
      .andExpect(status().isForbidden());

    mvc.perform(get("/iam/account-linking/OIDC/done").with(csrf().asHeader()))
      .andExpect(status().isForbidden());

    mvc.perform(delete("/iam/account-linking/OIDC").param("sub", "sub")
      .param("iss", "iss")
      .with(csrf().asHeader())).andExpect(status().isForbidden());

    mvc.perform(post("/iam/account-linking/SAML").with(csrf().asHeader()))
      .andExpect(status().isForbidden());

    mvc.perform(get("/iam/account-linking/SAML/done").with(csrf().asHeader()))
      .andExpect(status().isForbidden());

    mvc
      .perform(delete("/iam/account-linking/SAML").param("sub", "sub")
        .param("iss", "iss")
        .param("attr", "attr")
        .with(csrf().asHeader()))
      .andExpect(status().isForbidden());

  }



}
