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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.text.ParseException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.cache.RedisCacheManagerBuilderCustomizer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import io.restassured.RestAssured;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.config.CacheConfig;
import it.infn.mw.iam.config.RedisCacheProperties;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.redis.RedisContainer;



@Testcontainers
@IamMockMvcIntegrationTest
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {"iam.access_token.include_scope=true", "redis-cache.enabled=true"})
public class ScopeMatcherExternalCacheTests extends EndpointsTestUtils {

  private static final String CLIENT_ID = "cache-client";
  private static final String CLIENT_SECRET = "secret";

  static {
    System.setProperty("spring.devtools.restart.enabled", "false");
  }

  @Autowired
  private ClientService clientService;

  @Autowired
  private CacheConfig cacheConfig;

  @Autowired
  private RedisCacheProperties redisCacheProperties;

  @LocalServerPort
  private Integer iamPort;

  @Autowired
  ObjectMapper mapper;

  @Container
  private static final RedisContainer REDIS = new RedisContainer();

  @DynamicPropertySource
  static void redisProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.redis.port", REDIS::getFirstMappedPort);

  }

  @BeforeEach
  public void setup() {
    TestUtils.initRestAssured();
    RestAssured.port = iamPort;
    assertTrue(redisCacheProperties.isEnabled());
    assertThat(cacheConfig.redisCacheConfiguration(), instanceOf(RedisCacheConfiguration.class));
    assertThat(cacheConfig.redisCacheManagerBuilderCustomizer(),
        instanceOf(RedisCacheManagerBuilderCustomizer.class));

  }

  private String getAccessTokenForClient(String scopes) throws Exception {

    return new AccessTokenGetter().grantType("client_credentials")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .scope(scopes)
      .getAccessTokenValue();

  }

  @Test
  public void ensureRedisRunning() {
    assertTrue(REDIS.isRunning());
  }

  @Test
  public void updatingClientScopesInvalidatesExternalCache() throws ParseException, Exception {

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
