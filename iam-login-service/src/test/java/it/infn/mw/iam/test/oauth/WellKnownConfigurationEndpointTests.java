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

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.collect.Sets;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.core.web.wellknown.IamDiscoveryEndpoint;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;
import it.infn.mw.iam.persistence.model.SystemScope;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = "task.wellKnownCacheCleanupPeriodSecs=1")
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles({"h2-test"})
class WellKnownConfigurationEndpointTests {

  private String endpoint = "/" + IamDiscoveryEndpoint.OPENID_CONFIGURATION_URL;

  private Set<String> iamSupportedGrants =
      Sets.newLinkedHashSet(Arrays.asList("authorization_code", "implicit", "refresh_token",
          "client_credentials", "password", "urn:ietf:params:oauth:grant-type:token-exchange",
          "urn:ietf:params:oauth:grant-type:device_code"));

  private static final String IAM_ORGANISATION_NAME_CLAIM = "organisation_name";
  private static final String IAM_GROUPS_CLAIM = "groups";
  private static final String IAM_EXTERNAL_AUTHN_CLAIM = "external_authn";

  private static final String SYSTEM_SCOPE_0 = "new-scope0";
  private static final String SYSTEM_SCOPE_1 = "new-scope1";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private SystemScopeService scopeService;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private CacheManager cacheManager;

  private void evictWellKnownCache() {
    Cache cache = cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY);
    if (cache != null) {
      cache.clear();
    }
  }

  @Test
  void testGrantTypesSupported() throws Exception {

    // @formatter:off
    mvc.perform(get(endpoint))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.grant_types_supported").isNotEmpty())
        .andExpect(jsonPath("$.grant_types_supported").isArray())
        .andExpect(jsonPath("$.grant_types_supported").value(containsInAnyOrder(iamSupportedGrants.toArray())));
    // @formatter:on
  }

  @Test
  void testSupportedClaims() throws Exception {

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
  void testIssuerEndsWithSlash() throws Exception {
    mvc.perform(get(endpoint))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.issuer").value("http://localhost:8080/"));
  }

  @Test
  void testEndpoints() throws Exception {

    mvc.perform(get(endpoint))
      .andExpect(status().isOk())
      .andExpect(
          jsonPath("$.device_authorization_endpoint").value("http://localhost:8080/devicecode"))
      .andExpect(jsonPath("$.token_endpoint").value("http://localhost:8080/token"))
      .andExpect(jsonPath("$.authorization_endpoint").value("http://localhost:8080/authorize"))
      .andExpect(jsonPath("$.registration_endpoint")
        .value("http://localhost:8080/iam/api/client-registration"))
      .andExpect(jsonPath("$.introspection_endpoint").value("http://localhost:8080/introspect"))
      .andExpect(jsonPath("$.revocation_endpoint").value("http://localhost:8080/revoke"))
      .andExpect(jsonPath("$.userinfo_endpoint").value("http://localhost:8080/userinfo"))
      .andExpect(jsonPath("$.jwks_uri").value("http://localhost:8080/jwk"))
      .andExpect(jsonPath("$.scim_endpoint").value("http://localhost:8080/scim"));
  }

  @Test
  void testScopes() throws Exception {

    Set<String> unrestrictedScopes = scopeService.getUnrestricted()
      .stream()
      .map(SystemScope::getValue)
      .collect(Collectors.toSet());


    String responseJson = mvc.perform(get(endpoint))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scopes_supported").exists())
      .andReturn()
      .getResponse()
      .getContentAsString();


    ArrayNode scopesSupported = (ArrayNode) mapper.readTree(responseJson).get("scopes_supported");

    Set<String> returnedScopes = Sets.newHashSet();

    Iterator<JsonNode> scopesIterator = scopesSupported.iterator();
    while (scopesIterator.hasNext()) {
      returnedScopes.add(scopesIterator.next().asText());
    }

    assertTrue(returnedScopes.containsAll(unrestrictedScopes));

  }

  @Test
  void testWellKnownCacheEviction() throws Exception {

    SystemScope scope = new SystemScope(SYSTEM_SCOPE_0);
    scopeService.create(scope);

    mvc.perform(get(endpoint))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scopes_supported").exists())
      .andExpect(jsonPath("$.scopes_supported").isArray())
      .andExpect(jsonPath("$.scopes_supported", hasItem(SYSTEM_SCOPE_0)));

    scope = new SystemScope(SYSTEM_SCOPE_1);
    scopeService.create(scope);

    mvc.perform(get(endpoint))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scopes_supported").exists())
      .andExpect(jsonPath("$.scopes_supported").isArray())
      .andExpect(jsonPath("$.scopes_supported", not(SYSTEM_SCOPE_1)));

    evictWellKnownCache();

    mvc.perform(get(endpoint))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scopes_supported").exists())
      .andExpect(jsonPath("$.scopes_supported").isArray())
      .andExpect(jsonPath("$.scopes_supported", hasItem(SYSTEM_SCOPE_1)));

  }

}
