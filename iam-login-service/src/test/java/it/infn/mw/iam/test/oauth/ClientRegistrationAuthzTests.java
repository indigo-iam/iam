/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
package it.infn.mw.iam.test.oauth;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.WithAnonymousUser;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebAppConfiguration
@Transactional
@WithAnonymousUser
@TestPropertySource(properties= {"clientRegistration.allowFor=REGISTERED_USERS"})
public class ClientRegistrationAuthzTests extends ClientRegistrationTestSupport {

  @Autowired
  private WebApplicationContext context;

  private MockMvc mvc;

  @Before
  public void setup() throws Exception {
    mvc = MockMvcBuilders.webAppContextSetup(context)
      .apply(springSecurity())
      .alwaysDo(log())
      .build();
  }

  @Test
  public void testClientRegistrationRequiresAuthenticatedUser() throws Exception {

    String jsonInString = ClientJsonStringBuilder.builder().scopes("test").build();

    mvc.perform(post(REGISTER_ENDPOINT).contentType(APPLICATION_JSON).content(jsonInString))
      .andExpect(status().isUnauthorized());
  }
  
  @WithMockUser(username="test", roles="USER")
  public void testClientRegistrationWorksForAuthenticatedUser() throws Exception {

    String jsonInString = ClientJsonStringBuilder.builder().scopes("test").build();

    mvc.perform(post(REGISTER_ENDPOINT).contentType(APPLICATION_JSON).content(jsonInString))
      .andExpect(status().isCreated());
  }
  
  @WithMockUser(username="admin", roles="ADMIN")
  public void testClientRegistrationWorksForAdminUser() throws Exception {

    String jsonInString = ClientJsonStringBuilder.builder().scopes("test").build();

    mvc.perform(post(REGISTER_ENDPOINT).contentType(APPLICATION_JSON).content(jsonInString))
      .andExpect(status().isCreated());
  }

}
