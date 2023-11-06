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
package it.infn.mw.iam.test.api.client;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.registration.ClientRegistrationApiController;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@WithMockUser(username = "test", roles = "USER")
@SpringBootTest(classes = {IamLoginService.class})
public class ClientRegistrationAPIIntegrationTests extends TestSupport {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Test
  @WithAnonymousUser
  public void dynamicRegistrationWorksForAnonymousUser() throws Exception {

    String clientJson = ClientJsonStringBuilder.builder().scopes("openid").build();

    mvc
      .perform(post(ClientRegistrationApiController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(CREATED)
      .andExpect(jsonPath("$.client_id").exists())
      .andExpect(jsonPath("$.client_secret").exists())
      .andExpect(jsonPath("$.client_name").exists())
      .andExpect(jsonPath("$.grant_types").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.dynamically_registered").value(true))
      .andExpect(jsonPath("$.registration_access_token").exists());

  }

  @Test
  public void clientDetailsVisibleWithAuthentication() throws Exception {

    String clientJson = ClientJsonStringBuilder.builder().scopes("openid").build();

    String responseJson = mvc
      .perform(post(ClientRegistrationApiController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(CREATED)
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO client = mapper.readValue(responseJson, RegisteredClientDTO.class);

    final String url =
        String.format("%s/%s", ClientRegistrationApiController.ENDPOINT, client.getClientId());

    mvc.perform(get(url))
      .andExpect(OK)
      .andExpect(jsonPath("$.client_id").value(client.getClientId()))
      .andExpect(jsonPath("$.client_name").value(client.getClientName()));

  }

  @Test
  public void clientRemovalWorksWithAuthentication() throws Exception {

    String clientJson = ClientJsonStringBuilder.builder().scopes("openid").build();

    String responseJson = mvc
      .perform(post(ClientRegistrationApiController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(CREATED)
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO client = mapper.readValue(responseJson, RegisteredClientDTO.class);

    final String url =
        String.format("%s/%s", ClientRegistrationApiController.ENDPOINT, client.getClientId());

    mvc.perform(delete(url)).andExpect(NO_CONTENT);

    mvc.perform(get(url))
      .andExpect(NOT_FOUND)
      .andExpect(jsonPath("$.error", containsString("Client not found")));
  }

  @Test
  public void tokenLifetimesAreNotEditable() throws Exception {

    String clientJson = ClientJsonStringBuilder.builder()
      .scopes("openid")
      .accessTokenValiditySeconds(10)
      .refreshTokenValiditySeconds(10)
      .build();

    mvc
      .perform(post(ClientRegistrationApiController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(CREATED)
      .andExpect(jsonPath("$.access_token_validity_seconds").doesNotExist())
      .andExpect(jsonPath("$.refresh_token_validity_seconds").doesNotExist());

  }

}
