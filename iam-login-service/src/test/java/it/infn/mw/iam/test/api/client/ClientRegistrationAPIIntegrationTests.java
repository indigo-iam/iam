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

import static java.lang.String.format;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.registration.ClientRegistrationApiController;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;

@SpringBootTest(classes = {IamLoginService.class})
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@TestPropertySource(properties = {
    "spring.main.allow-bean-definition-overriding=true",
})
@Transactional
class ClientRegistrationAPIIntegrationTests extends TestSupport {

  @Autowired
  MockMvc mvc;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  IamClientRepository clientRepository;

  @Test
  @WithAnonymousUser
  @Transactional
  public void dynamicRegistrationWorksForAnonymousUser() throws Exception {

    String clientJson =
        ClientJsonStringBuilder.builder().scopes("openid").grantTypes("authorization_code").build();

    String responseJson = mvc
      .perform(post(ClientRegistrationApiController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(CREATED)
      .andExpect(jsonPath("$.client_id").exists())
      .andExpect(jsonPath("$.client_secret").exists())
      .andExpect(jsonPath("$.client_name").exists())
      .andExpect(jsonPath("$.grant_types").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.dynamically_registered").value(true))
      .andExpect(jsonPath("$.registration_access_token").exists())
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO client = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertNotNull(client.getClientSecret());
  }

  @Test
  @WithAnonymousUser
  @Transactional
  public void dynamicRegistrationNotWorksForAnonymousUserWithGrantTypeClientCredentials()
      throws Exception {

    String clientJson =
        ClientJsonStringBuilder.builder().scopes("openid").grantTypes("client_credentials").build();

    mvc
      .perform(post(ClientRegistrationApiController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(BAD_REQUEST);
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  @Transactional
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
  @WithMockUser(username = "test", roles = "USER")
  @Transactional
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
  @WithAnonymousUser
  @Transactional
  public void clientRemovalWorksWithRatAuthentication() throws Exception {

    String clientJson =
        ClientJsonStringBuilder.builder().scopes("openid").grantTypes("authorization_code").build();

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

    mvc
      .perform(delete(url).header(HttpHeaders.AUTHORIZATION,
          "Bearer " + client.getRegistrationAccessToken()))
      .andExpect(NO_CONTENT);

    mvc.perform(get(url))
      .andExpect(NOT_FOUND)
      .andExpect(jsonPath("$.error", containsString("Client not found")));
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  @Transactional
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

  @Test
  @WithAnonymousUser
  @Transactional
  void testReturnClientSecret() throws Exception {
    String clientJsonRequest = ClientJsonStringBuilder.builder()
      .scopes("openid")
      .grantTypes("authorization_code")
      .accessTokenValiditySeconds(10)
      .refreshTokenValiditySeconds(10)
      .build();

    String responseJson = mvc
      .perform(post(ClientRegistrationApiController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJsonRequest))
      .andExpect(CREATED)
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO client = mapper.readValue(responseJson, RegisteredClientDTO.class);
    String clientSecret = client.getClientSecret();
    assertNotNull(clientSecret);

    client.setClientSecret("secret");

    String RAT = format("Bearer %s", client.getRegistrationAccessToken());

    responseJson = mvc
      .perform(put(ClientRegistrationApiController.ENDPOINT + "/" + client.getClientId())
        .header(HttpHeaders.AUTHORIZATION, RAT)
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(OK)
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO clientDto = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertNull(clientDto.getClientSecret());

    clientRepository.findByClientId(client.getClientId()).ifPresentOrElse(c -> {
      assertEquals(clientSecret, c.getClientSecret());
    }, () -> {
      throw new AssertionError("Client not found");
    });
  }

  @Test
  @WithAnonymousUser
  @Transactional
  void testClientPublicWithoutSecret() throws Exception {
    RegisteredClientDTO publicClient = new RegisteredClientDTO();
    publicClient.setClientName("test-public-client");
    publicClient.setGrantTypes(Set.of(AuthorizationGrantType.CODE));
    publicClient.setScope(Set.of("openid"));
    publicClient.setRedirectUris(Set.of("https://test.example/cb"));
    publicClient.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.none);

    String clientJsonRequest = mapper.writeValueAsString(publicClient);

    String responseJson = mvc
      .perform(post(ClientRegistrationApiController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJsonRequest))
      .andExpect(CREATED)
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO client = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertNull(client.getClientSecret());

    RegisteredClientDTO publicClient2 = new RegisteredClientDTO();
    publicClient2.setClientName("test-public-client");
    publicClient2.setClientId(client.getClientId());
    publicClient2.setGrantTypes(Set.of(AuthorizationGrantType.CODE));
    publicClient2.setScope(Set.of("openid"));
    publicClient2.setRedirectUris(Set.of("https://test.example/cb"));
    publicClient2.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.none);
    publicClient2.setRegistrationAccessToken(null);

    // Now try to update the public client by providing a client secret
    publicClient2.setClientSecret("secret");

    responseJson =
        mvc
          .perform(put(ClientRegistrationApiController.ENDPOINT + "/" + client.getClientId())
            .header(HttpHeaders.AUTHORIZATION,
                format("Bearer %s", client.getRegistrationAccessToken()))
            .contentType(APPLICATION_JSON)
            .content(mapper.writeValueAsString(publicClient2)))
          .andExpect(OK)
          .andReturn()
          .getResponse()
          .getContentAsString();

    RegisteredClientDTO clientDto = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertNull(clientDto.getClientSecret());
    assertNull(clientDto.getRegistrationAccessToken());
  }

}
