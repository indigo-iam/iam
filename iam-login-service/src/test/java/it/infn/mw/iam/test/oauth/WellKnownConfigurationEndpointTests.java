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
package it.infn.mw.iam.test.oauth;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.SystemScopeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.collect.Sets;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.web.wellknown.IamDiscoveryEndpoint;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class WellKnownConfigurationEndpointTests {

  private String endpoint = "/" + IamDiscoveryEndpoint.OPENID_CONFIGURATION_URL;

  private Set<String> iamSupportedGrants =
      Sets.newLinkedHashSet(Arrays.asList("authorization_code", "implicit", "refresh_token",
          "client_credentials", "password", "urn:ietf:params:oauth:grant-type:token-exchange",
          "urn:ietf:params:oauth:grant-type:device_code"));

  private static final String IAM_ORGANISATION_NAME_CLAIM = "organisation_name";
  private static final String IAM_GROUPS_CLAIM = "groups";
  private static final String IAM_EXTERNAL_AUTHN_CLAIM = "external_authn";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private SystemScopeService scopeService;

  @Autowired
  private ObjectMapper mapper;

  @Test
  public void testGrantTypesSupported() throws Exception {

    // @formatter:off
    mvc.perform(get(endpoint))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.grant_types_supported").isNotEmpty())
        .andExpect(jsonPath("$.grant_types_supported").isArray())
        .andExpect(jsonPath("$.grant_types_supported").value(containsInAnyOrder(iamSupportedGrants.toArray())));
    // @formatter:on
  }

  @Test
  public void testSupportedClaims() throws Exception {

    // @formatter:off
    mvc.perform(get(endpoint))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.claims_supported").isNotEmpty())
        .andExpect(jsonPath("$.claims_supported").isArray())
        .andExpect(jsonPath("$.claims_supported", hasItem(IAM_ORGANISATION_NAME_CLAIM)))
        .andExpect(jsonPath("$.claims_supported", hasItem(IAM_GROUPS_CLAIM)))
        .andExpect(jsonPath("$.claims_supported", hasItem(IAM_EXTERNAL_AUTHN_CLAIM)));
    // @formatter:on
  }

  @Test
  public void testIssuerEndsWithSlash() throws Exception {
    mvc.perform(get(endpoint))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.issuer", is("http://localhost:8080/")));
  }

  @Test
  public void testEndpoints() throws Exception {

    mvc.perform(get(endpoint))
      .andExpect(status().isOk())
      .andExpect(
          jsonPath("$.device_authorization_endpoint", is("http://localhost:8080/devicecode")))
      .andExpect(jsonPath("$.token_endpoint", is("http://localhost:8080/token")))
      .andExpect(jsonPath("$.authorization_endpoint", is("http://localhost:8080/authorize")))
      .andExpect(jsonPath("$.registration_endpoint",
          is("http://localhost:8080/iam/api/client-registration")))
      .andExpect(jsonPath("$.introspection_endpoint", is("http://localhost:8080/introspect")))
      .andExpect(jsonPath("$.revocation_endpoint", is("http://localhost:8080/revoke")))
      .andExpect(jsonPath("$.userinfo_endpoint", is("http://localhost:8080/userinfo")))
      .andExpect(jsonPath("$.jwks_uri", is("http://localhost:8080/jwk")));
  }

  @Test
  public void testScopes() throws Exception {

    Set<String> unrestrictedScopes = scopeService.getUnrestricted()
      .stream()
      .map(SystemScope::getValue)
      .collect(Collectors.toSet());

    
    String responseJson = 
    mvc.perform(get(endpoint))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scopes_supported", notNullValue()))
      .andReturn().getResponse().getContentAsString();

    
    ArrayNode scopesSupported  = (ArrayNode) mapper.readTree(responseJson).get("scopes_supported");
    
    Set<String> returnedScopes = Sets.newHashSet();

    Iterator<JsonNode> scopesIterator = scopesSupported.iterator();
    while (scopesIterator.hasNext()) {
      returnedScopes.add(scopesIterator.next().asText());
    }
    
    assertTrue(returnedScopes.containsAll(unrestrictedScopes));

  }

}
