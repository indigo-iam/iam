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

import java.text.ParseException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.cache.support.NoOpCacheManager;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"cache.enabled=false", "iam.access_token.include_scope=true"})
public class ScopeMatcherNoCacheTests extends EndpointsTestUtils {

  private static final String CLIENT_ID = "cache-client";
  private static final String CLIENT_SECRET = "secret";

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private CacheManager cacheManager;

  private String getAccessTokenForClient(String scopes) throws Exception {

    return new AccessTokenGetter().grantType("client_credentials")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .scope(scopes)
      .getAccessTokenValue();
  }

  @Test
  public void ensureRedisCacheIsDisabled() {
    assertThat(cacheManager, instanceOf(NoOpCacheManager.class));
    assertThat(cacheManager, not(instanceOf(ConcurrentMapCacheManager.class)));
    assertThat(cacheManager, not(instanceOf(RedisCacheManager.class)));
  }

  @Test
  public void updatingClientScopesWithNoCache() throws ParseException, Exception {

    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setClientId(CLIENT_ID);
    client.setClientSecret(CLIENT_SECRET);
    client.setScope(Sets.newHashSet("openid", "profile", "email"));
    clientRepo.save(client);

    try {
      JWT token = JWTParser.parse(getAccessTokenForClient("openid profile email"));
      assertThat("scim:read",
          not(in(token.getJWTClaimsSet().getClaim("scope").toString().split(" "))));
      client.setScope(Sets.newHashSet("openid", "profile", "email", "scim:read"));
      clientRepo.save(client);
      token = JWTParser.parse(getAccessTokenForClient("openid profile email scim:read"));
      assertThat("scim:read", in(token.getJWTClaimsSet().getClaim("scope").toString().split(" ")));
    } finally {
      clientRepo.delete(client);
    }
  }
}
