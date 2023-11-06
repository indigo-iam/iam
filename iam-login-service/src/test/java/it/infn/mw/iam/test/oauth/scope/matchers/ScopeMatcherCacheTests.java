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
package it.infn.mw.iam.test.oauth.scope.matchers;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.in;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertFalse;

import java.text.ParseException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.config.CacheConfig;
import it.infn.mw.iam.config.RedisCacheProperties;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"iam.access_token.include_scope=true"})
public class ScopeMatcherCacheTests extends EndpointsTestUtils {

  private static final String CLIENT_ID = "cache-client";
  private static final String CLIENT_SECRET = "secret";

  @Autowired
  private ClientService clientService;

  @Autowired
  private CacheConfig cacheConfig;
  
  @Autowired
  private RedisCacheProperties redisCacheProperties;

  private String getAccessTokenForClient(String scopes) throws Exception {

    return new AccessTokenGetter().grantType("client_credentials")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .scope(scopes)
      .getAccessTokenValue();
  }

  @Test
  public void ensureRedisCashIsDisabled() {
    assertFalse(redisCacheProperties.isEnabled());
    assertThat(cacheConfig.localCacheManager(), instanceOf(CacheManager.class));
  }

  @Test
  public void updatingClientScopesInvalidatesCache() throws ParseException, Exception {

    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setClientId(CLIENT_ID);
    client.setClientSecret(CLIENT_SECRET);
    client.setScope(Sets.newHashSet("openid", "profile", "email"));
    client = clientService.saveNewClient(client);

    try {
      JWT token = JWTParser.parse(getAccessTokenForClient("openid profile email"));
      assertThat("scim:read",
          not(in(token.getJWTClaimsSet().getClaim("scope").toString().split(" "))));
      client.setScope(Sets.newHashSet("openid", "profile", "email", "scim:read"));
      clientService.updateClient(client);
      token = JWTParser.parse(getAccessTokenForClient("openid profile email scim:read"));
      assertThat("scim:read", in(token.getJWTClaimsSet().getClaim("scope").toString().split(" ")));
    } finally {
      clientService.deleteClient(client);
    }
  }
}
