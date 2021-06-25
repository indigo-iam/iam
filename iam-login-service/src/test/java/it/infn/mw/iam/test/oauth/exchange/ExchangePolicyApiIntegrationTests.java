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
package it.infn.mw.iam.test.oauth.exchange;

import static it.infn.mw.iam.api.exchange_policy.ClientMatchingPolicyDTO.anyClient;
import static it.infn.mw.iam.api.exchange_policy.ClientMatchingPolicyDTO.clientById;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.exchange_policy.ClientMatchingPolicyDTO;
import it.infn.mw.iam.api.exchange_policy.ExchangePolicyDTO;
import it.infn.mw.iam.api.exchange_policy.ExchangeScopePolicyDTO;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdp;
import it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;
import it.infn.mw.iam.persistence.repository.IamTokenExchangePolicyRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    TokenExchangePdpTestSupport.class})
@WebAppConfiguration
@Transactional
@WithAnonymousUser
public class ExchangePolicyApiIntegrationTests {

  public static final String ENDPOINT = "/iam/api/exchange/policies";

  @Autowired
  private WebApplicationContext context;

  @Autowired
  MockOAuth2Filter filter;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  IamTokenExchangePolicyRepository repo;

  @Autowired
  TokenExchangePdp pdp;

  private MockMvc mvc;

  @Before
  public void setup() throws Exception {
    mvc =
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
  }


  protected ExchangePolicyDTO denyAllExchangesPolicy() {
    ExchangePolicyDTO policy = ExchangePolicyDTO.denyPolicy("Deny all exchanges");
    policy.setOriginClient(anyClient());
    policy.setDestinationClient(anyClient());
    return policy;
  }

  @After
  public void cleanupOAuthUser() {
    filter.cleanupSecurityContext();
  }


  @Test
  public void listPoliciesRequiresAuthenticatedUser() throws Exception {
    mvc.perform(get(ENDPOINT)).andExpect(status().isUnauthorized());
  }


  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"})
  public void listPoliciesRequiresAdmin() throws Exception {
    mvc.perform(get(ENDPOINT)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void listPoliciesWorks() throws Exception {
    mvc.perform(get(ENDPOINT))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").value(hasSize(1)))
      .andExpect(jsonPath("$[0].description").value("Allow all exchanges"))
      .andExpect(jsonPath("$[0].rule").value("PERMIT"))
      .andExpect(jsonPath("$[0].originClient.type").value("ANY"))
      .andExpect(jsonPath("$[0].destinationClient.type").value("ANY"));
  }

  @Test
  public void deletePolicyRequiresAuthenticatedUser() throws Exception {
    mvc.perform(delete(ENDPOINT + "/1")).andExpect(status().isUnauthorized());
  }


  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"})
  public void deletePolicyRequiresAdminUser() throws Exception {
    mvc.perform(delete(ENDPOINT + "/1")).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void deletePolicyWorks() throws Exception {
    mvc.perform(delete(ENDPOINT + "/1")).andExpect(status().isNoContent());
    mvc.perform(delete(ENDPOINT + "/1")).andExpect(status().isNotFound());
  }


  @Test
  public void createPolicyRequiresAuthenticatedUser() throws Exception {
    String policy = mapper.writeValueAsString(denyAllExchangesPolicy());
    mvc.perform(post(ENDPOINT).content(policy)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"})
  public void createPolicyRequiresAdminUser() throws Exception {
    String policy = mapper.writeValueAsString(denyAllExchangesPolicy());
    mvc.perform(post(ENDPOINT).content(policy).contentType(APPLICATION_JSON))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void createPolicyWorks() throws Exception {
    repo.deleteAll();

    String policy = mapper.writeValueAsString(denyAllExchangesPolicy());
    mvc.perform(post(ENDPOINT).content(policy).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    mvc.perform(get(ENDPOINT))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").value(hasSize(1)))
      .andExpect(jsonPath("$[0].description").value("Deny all exchanges"))
      .andExpect(jsonPath("$[0].rule").value("DENY"))
      .andExpect(jsonPath("$[0].originClient.type").value("ANY"))
      .andExpect(jsonPath("$[0].destinationClient.type").value("ANY"));

    mvc.perform(post(ENDPOINT).content(policy).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    mvc.perform(get(ENDPOINT))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").value(hasSize(2)))
      .andExpect(jsonPath("$[0].description").value("Deny all exchanges"))
      .andExpect(jsonPath("$[0].rule").value("DENY"))
      .andExpect(jsonPath("$[0].originClient.type").value("ANY"))
      .andExpect(jsonPath("$[0].destinationClient.type").value("ANY"))
      .andExpect(jsonPath("$[1].description").value("Deny all exchanges"))
      .andExpect(jsonPath("$[1].rule").value("DENY"))
      .andExpect(jsonPath("$[1].originClient.type").value("ANY"))
      .andExpect(jsonPath("$[1].destinationClient.type").value("ANY"));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void cleanPolicyCachePolicyWorks() throws Exception {
    repo.deleteAll();

    String policy = mapper.writeValueAsString(denyAllExchangesPolicy());
    mvc.perform(post(ENDPOINT).content(policy).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    mvc.perform(post(ENDPOINT + "/clear-cache")).andExpect(status().isOk());

    verify(pdp).clearPolicyCache();
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void createPolicyWithScopePoliciesWorks() throws Exception {

    repo.deleteAll();

    ExchangePolicyDTO policyDto =
        ExchangePolicyDTO.permitPolicy("Permit policy with scope policies");

    ExchangeScopePolicyDTO allowAllScopes = new ExchangeScopePolicyDTO();
    allowAllScopes.setType(MatchingPolicy.REGEXP);
    allowAllScopes.setRule(PolicyRule.PERMIT);
    allowAllScopes.setMatchParam(".*");

    ExchangeScopePolicyDTO sp = new ExchangeScopePolicyDTO();

    sp.setType(MatchingPolicy.EQ);
    sp.setMatchParam("offline_access");
    sp.setRule(PolicyRule.DENY);

    policyDto.getScopePolicies().add(sp);
    policyDto.getScopePolicies().add(allowAllScopes);

    policyDto.setOriginClient(ClientMatchingPolicyDTO.anyClient());
    policyDto.setDestinationClient(ClientMatchingPolicyDTO.anyClient());

    String policy = mapper.writeValueAsString(policyDto);
    mvc.perform(post(ENDPOINT).content(policy).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    mvc.perform(get(ENDPOINT))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").value(hasSize(1)))
      .andExpect(jsonPath("$[0].description").value("Permit policy with scope policies"))
      .andExpect(jsonPath("$[0].rule").value("PERMIT"))
      .andExpect(jsonPath("$[0].originClient.type").value("ANY"))
      .andExpect(jsonPath("$[0].destinationClient.type").value("ANY"))
      .andExpect(
          jsonPath("$[0].scopePolicies[?(@.matchParam=='offline_access')].rule").value("DENY"))
      .andExpect(jsonPath("$[0].scopePolicies[?(@.matchParam=='offline_access')].type").value("EQ"))
      .andExpect(jsonPath("$[0].scopePolicies[?(@.matchParam=='.*')].rule").value("PERMIT"))
      .andExpect(jsonPath("$[0].scopePolicies[?(@.matchParam=='.*')].type").value("REGEXP"));
  }



  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void policyValidation() throws Exception {

    // Empty object
    ObjectNode node = mapper.createObjectNode();
    mvc
      .perform(
          post(ENDPOINT).content(mapper.writeValueAsString(node)).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("Invalid token exchange policy")));

    // Invalid rule
    node = mapper.createObjectNode();
    node.put("rule", "WHATEVER");

    mvc
      .perform(
          post(ENDPOINT).content(mapper.writeValueAsString(node)).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(
          jsonPath("$.error", containsString("could not parse the policy JSON representation")));

    // Long description
    ExchangePolicyDTO longDescriptionPolicy = denyAllExchangesPolicy();
    longDescriptionPolicy.setDescription(RandomStringUtils.randomAlphanumeric(513));
    mvc
      .perform(post(ENDPOINT).content(mapper.writeValueAsString(longDescriptionPolicy))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error",
          containsString("the description string must be at most 512 characters long")));

    // Invalid origin client
    node = mapper.createObjectNode();
    node.put("rule", "DENY");
    ObjectNode originClient = mapper.createObjectNode();
    ObjectNode destClient = mapper.createObjectNode();
    originClient.put("type", "WHATEVER");
    destClient.put("type", "ANY");

    node.set("originClient", originClient);
    node.set("destinationClient", destClient);

    mvc
      .perform(
          post(ENDPOINT).content(mapper.writeValueAsString(node)).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(
          jsonPath("$.error", containsString("could not parse the policy JSON representation")));

    // Invalid destination client
    node = mapper.createObjectNode();
    node.put("rule", "DENY");
    originClient = mapper.createObjectNode();
    destClient = mapper.createObjectNode();
    destClient.put("type", "WHATEVER");
    originClient.put("type", "ANY");

    node.set("originClient", originClient);
    node.set("destinationClient", destClient);

    mvc
      .perform(
          post(ENDPOINT).content(mapper.writeValueAsString(node)).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(
          jsonPath("$.error", containsString("could not parse the policy JSON representation")));

    // Long match param checks
    ExchangePolicyDTO longMatchParamPolicy = denyAllExchangesPolicy();
    longMatchParamPolicy.setOriginClient(clientById(randomAlphanumeric(257)));

    mvc
      .perform(post(ENDPOINT).content(mapper.writeValueAsString(longMatchParamPolicy))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("must be at most 256")));
  }
}
