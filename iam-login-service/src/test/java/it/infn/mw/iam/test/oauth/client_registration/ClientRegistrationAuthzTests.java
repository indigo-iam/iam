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
package it.infn.mw.iam.test.oauth.client_registration;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"client-registration.allow-for=REGISTERED_USERS"})
public class ClientRegistrationAuthzTests extends ClientRegistrationTestSupport {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamAccountClientRepository accountClientRepo;

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamAccountRepository accountRepo;

  @Test
  public void testClientRegistrationRequiresAuthenticatedUser() throws Exception {

    String jsonInString = ClientJsonStringBuilder.builder().scopes("test").build();

    mvc.perform(post(REGISTER_ENDPOINT).contentType(APPLICATION_JSON).content(jsonInString))
      .andExpect(status().isForbidden());
  }

  @WithMockUser(username = "test", roles = "USER")
  @Test
  public void testClientRegistrationWorksForAuthenticatedUser() throws Exception {

    IamAccount testAccount = accountRepo.findByUsername("test").orElseThrow();

    String jsonInString = ClientJsonStringBuilder.builder().scopes("test").build();

    String responseJson =
        mvc.perform(post(REGISTER_ENDPOINT).contentType(APPLICATION_JSON).content(jsonInString))
          .andExpect(status().isCreated())
          .andReturn()
          .getResponse()
          .getContentAsString();

    RegisteredClientDTO response = mapper.readValue(responseJson, RegisteredClientDTO.class);

    ClientDetailsEntity client = clientRepo.findByClientId(response.getClientId()).orElseThrow();
    accountClientRepo.findByAccountAndClient(testAccount, client).orElseThrow();
  }

  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  @Test
  public void testClientRegistrationWorksForAdminUser() throws Exception {

    IamAccount adminAccount = accountRepo.findByUsername("admin").orElseThrow();

    String jsonInString = ClientJsonStringBuilder.builder().scopes("test").build();

    String responseJson =
        mvc.perform(post(REGISTER_ENDPOINT).contentType(APPLICATION_JSON).content(jsonInString))
          .andExpect(status().isCreated())
          .andReturn()
          .getResponse()
          .getContentAsString();

    RegisteredClientDTO response = mapper.readValue(responseJson, RegisteredClientDTO.class);

    ClientDetailsEntity client = clientRepo.findByClientId(response.getClientId()).orElseThrow();
    accountClientRepo.findByAccountAndClient(adminAccount, client).orElseThrow();
  }

}
