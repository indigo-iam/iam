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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.management.ClientManagementAPIController;
import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.client.registration.ClientRegistrationApiController;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.core.client.IamSha256PasswordEncoder;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ClientRegistrationAPIIntegrationTests implements StructuredScopeTestSupportConstants {

  @Autowired
  MockMvc mvc;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  IamClientRepository clientRepository;

  @Autowired
  ClientManagementService clientService;

  @BeforeEach
  void setup() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void dynamicRegistrationWorksForAnonymousUser() throws Exception {

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

    clientService.deleteClientByClientId(client.getClientId());
  }

  @Test
  void dynamicRegistrationNotWorksForAnonymousUserWithGrantTypeClientCredentials()
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
  void clientDetailsVisibleWithAuthentication() throws Exception {

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

    clientService.deleteClientByClientId(client.getClientId());
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  void clientRemovalWorksWithAuthentication() throws Exception {

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
  void clientRemovalWorksWithRatAuthentication() throws Exception {

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

    SecurityContextHolder.clearContext();

    mvc.perform(get(url))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", containsString("Invalid registration access token")));
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  void tokenLifetimesAreNotEditable() throws Exception {

    String clientJson = ClientJsonStringBuilder.builder()
      .scopes("openid")
      .accessTokenValiditySeconds(10)
      .refreshTokenValiditySeconds(10)
      .build();

    String responseJson = mvc
      .perform(post(ClientRegistrationApiController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(CREATED)
      .andExpect(jsonPath("$.access_token_validity_seconds").doesNotExist())
      .andExpect(jsonPath("$.refresh_token_validity_seconds").doesNotExist())
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO client = mapper.readValue(responseJson, RegisteredClientDTO.class);

    clientService.deleteClientByClientId(client.getClientId());
  }

  @Test
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
      assertEquals(c.getClientSecret(), new IamSha256PasswordEncoder().encode(clientSecret));
    }, () -> {
      throw new AssertionError("Client not found");
    });

    clientService.deleteClientByClientId(client.getClientId());
  }

  @Test
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

    clientService.deleteClientByClientId(client.getClientId());
  }

  @ParameterizedTest
  @MethodSource("unsupportedClientMetadata")
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void clientCreationRejectsUnsupportedMetadata(String field, List<String> values)
      throws Exception {

    ObjectNode payload = validAuthorizationCodeClientPayload();
    replaceMetadata(payload, field, values);

    long clientsBefore = clientRepository.count();

    mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).with(csrf())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(payload)))
      .andExpect(status().isBadRequest());

    assertEquals(clientsBefore, clientRepository.count());
  }

  @ParameterizedTest
  @MethodSource("unsupportedClientMetadata")
  void dynamicRegistrationRejectsUnsupportedMetadata(String field, List<String> values)
      throws Exception {

    ObjectNode payload = validAuthorizationCodeClientPayload();
    replaceMetadata(payload, field, values);

    long clientsBefore = clientRepository.count();

    mvc
      .perform(post(ClientRegistrationApiController.ENDPOINT).with(csrf())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(payload)))
      .andExpect(status().isBadRequest());

    assertEquals(clientsBefore, clientRepository.count());
  }

  static Stream<Arguments> unsupportedClientMetadata() {
    return Stream.of(Arguments.of("grant_types", List.of("implicit")),
        Arguments.of("grant_types", List.of("authorization_code", "implicit")),
        Arguments.of("response_types", List.of("token")),
        Arguments.of("response_types", List.of("code", "token")),
        Arguments.of("response_types", List.of("id_token")),
        Arguments.of("response_types", List.of("token id_token")),
        Arguments.of("response_types", List.of("id_token token")),
        Arguments.of("response_types", List.of("code token")),
        Arguments.of("response_types", List.of("code id_token")),
        Arguments.of("response_types", List.of("code token id_token")));
  }

  @ParameterizedTest
  @MethodSource("unsupportedClientMetadata")
  void dynamicRegistrationUpdateRejectsUnsupportedMetadataWithoutChangingClient(String field,
      List<String> values) throws Exception {

    ObjectNode payload = validAuthorizationCodeClientPayload();

    String responseJson = mvc
      .perform(post(ClientRegistrationApiController.ENDPOINT).with(csrf())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(payload)))
      .andExpect(status().isCreated())
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO created = mapper.readValue(responseJson, RegisteredClientDTO.class);

    String clientId = created.getClientId();
    assertNotNull(created.getRegistrationAccessToken());

    ClientDetailsEntity before = clientRepository.findByClientId(clientId).orElseThrow();

    Set<String> originalGrantTypes = Set.copyOf(before.getGrantTypes());
    Set<String> originalResponseTypes = Set.copyOf(before.getResponseTypes());
    String originalName = before.getClientName();
    long clientsBefore = clientRepository.count();

    payload.put("client_id", clientId);
    payload.put("client_name", "This update must not be applied");
    replaceMetadata(payload, field, values);

    mvc
      .perform(put(ClientRegistrationApiController.ENDPOINT + "/" + clientId).with(csrf())
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + created.getRegistrationAccessToken())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(payload)))
      .andExpect(status().isBadRequest());

    ClientDetailsEntity after = clientRepository.findByClientId(clientId).orElseThrow();

    assertEquals(clientsBefore, clientRepository.count());
    assertEquals(originalGrantTypes, after.getGrantTypes());
    assertEquals(originalResponseTypes, after.getResponseTypes());
    assertEquals(originalName, after.getClientName());
  }

  private ObjectNode validAuthorizationCodeClientPayload() throws Exception {
    String json =
        ClientJsonStringBuilder.builder().scopes("openid").grantTypes("authorization_code").build();

    ObjectNode payload = (ObjectNode) mapper.readTree(json);

    payload.putArray("response_types").add("code");
    payload.putArray("redirect_uris").add("https://client.example.org/callback");

    return payload;
  }

  private void replaceMetadata(ObjectNode payload, String field, List<String> values) {

    ArrayNode array = payload.putArray(field);
    values.forEach(value -> array.add(value));
  }
}
