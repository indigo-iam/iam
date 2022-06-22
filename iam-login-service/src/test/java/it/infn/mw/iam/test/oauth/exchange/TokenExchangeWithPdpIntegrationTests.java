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
package it.infn.mw.iam.test.oauth.exchange;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.exchange_policy.ClientMatchingPolicyDTO;
import it.infn.mw.iam.api.exchange_policy.ExchangePolicyDTO;
import it.infn.mw.iam.api.exchange_policy.ExchangeScopePolicyDTO;
import it.infn.mw.iam.api.exchange_policy.TokenExchangePolicyService;
import it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@DirtiesContext
public class TokenExchangeWithPdpIntegrationTests extends EndpointsTestUtils {

  private static final String TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
  private static final String TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
  private static final String TOKEN_ENDPOINT = "/token";

  private static final String TEST_USER_USERNAME = "test";
  private static final String TEST_USER_PASSWORD = "password";

  @Autowired
  private TokenExchangePolicyService service;

  @Test
  public void testTokenExchangeBlockedWithNoPolicy() throws Exception {
    String clientId = "token-exchange-subject";
    String clientSecret = "secret";

    String actorClientId = "token-exchange-actor";
    String actorClientSecret = "secret";

    String accessToken = new AccessTokenGetter().grantType("password")
      .clientId(clientId)
      .clientSecret(clientSecret)
      .username(TEST_USER_USERNAME)
      .password(TEST_USER_PASSWORD)
      .scope("openid profile")
      .getAccessTokenValue();

    service.deleteAllTokenExchangePolicies();

    mvc.perform(post(TOKEN_ENDPOINT)
        .with(httpBasic(actorClientId, actorClientSecret))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE)
        .param("scope", "openid"))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error").value("access_denied"))
      .andExpect(
          jsonPath("$.error_description").value("No policy found authorizing this exchange"));

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
    policyDto.setDestinationClient(ClientMatchingPolicyDTO.clientById(actorClientId));

    service.createTokenExchangePolicy(policyDto);

    mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(actorClientId, actorClientSecret))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE)
        .param("scope", "openid"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope").value("openid"))
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.id_token").exists());

    mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(actorClientId, actorClientSecret))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE)
        .param("scope", "openid offline_access"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_scope"))
      .andExpect(jsonPath("$.error_description")
        .value("scope exchange not allowed by policy: offline_access"));


  }

}
