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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SuppressWarnings("deprecation")
public class ProtectedResourceAndTokenGrantTypesTests extends EndpointsTestUtils {

  static final String PROTECTED_RESOURCE_ID = "protected-resource-test";
  static final String PROTECTED_RESOURCE_SECRET = "secret";

  @Autowired
  private ClientService clientService;

  private ClientDetailsEntity protectedResource;

  @Before
  public void setup() {

    protectedResource = new ClientDetailsEntity();
    protectedResource.setGrantTypes(Set.of());
    protectedResource.setAllowIntrospection(true);
    protectedResource.setClientId(PROTECTED_RESOURCE_ID);
    protectedResource.setClientSecret(PROTECTED_RESOURCE_SECRET);
    protectedResource.setScope(Set.of("openid"));
    protectedResource = clientService.saveNewClient(protectedResource);
  }

  @After
  public void teardown() {

    clientService.deleteClient(protectedResource);
  }

  @Test
  public void testProtectedResourceGetsNoTokenWithClientCredentials() throws Exception {

    new AccessTokenGetter().grantType("client_credentials")
      .clientId(PROTECTED_RESOURCE_ID)
      .clientSecret(PROTECTED_RESOURCE_SECRET)
      .scope("openid")
      .performTokenRequest(401);
  }

  @Test
  public void testProtectedResourceGetsNoTokenWithPassword() throws Exception {

    new AccessTokenGetter().grantType("password")
      .clientId(PROTECTED_RESOURCE_ID)
      .clientSecret(PROTECTED_RESOURCE_SECRET)
      .scope("openid")
      .performTokenRequest(401);
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void testProtectedResourceGetsNoTokenWithImplicitFlow() throws Exception {

    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl("http://localhost/authorize")
      .queryParam("response_type", "token")
      .queryParam("client_id", PROTECTED_RESOURCE_ID)
      .queryParam("redirect_uri", "http://localhost:9876/implicit")
      .queryParam("scope", "openid profile")
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build();

    String authzEndpointUrl = uriComponents.toUriString();

    MvcResult result = mvc.perform(get(authzEndpointUrl))
      .andExpect(status().isBadRequest())
      .andExpect(view().name("forward:/oauth/error"))
      .andReturn();

    InvalidGrantException ex =
        (InvalidGrantException) result.getModelAndView().getModel().get("error");

    assertThat(ex).isInstanceOf(InvalidGrantException.class);
    assertThat(ex.getMessage()).isEqualTo("A client must have at least one authorized grant type.");
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void testProtectedResourceGetsNoTokenWithAuthorizationCode() throws Exception {

    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl("http://localhost/authorize")
      .queryParam("response_type", "code")
      .queryParam("client_id", PROTECTED_RESOURCE_ID)
      .queryParam("redirect_uri", "http://localhost:9876/code")
      .queryParam("scope", "openid")
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build();

    String authzEndpointUrl = uriComponents.toUriString();

    MvcResult errorResult = mvc
      .perform(get(authzEndpointUrl))
      .andExpect(status().isBadRequest())
      .andExpect(view().name("forward:/oauth/error"))
      .andReturn();

    InvalidGrantException ex =
        (InvalidGrantException) errorResult.getModelAndView().getModel().get("error");

    assertThat(ex).isInstanceOf(InvalidGrantException.class);
    assertThat(ex.getMessage()).isEqualTo("A client must have at least one authorized grant type.");
  }
}
