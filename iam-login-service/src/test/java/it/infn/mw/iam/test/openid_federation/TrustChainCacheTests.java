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
package it.infn.mw.iam.test.openid_federation;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Date;
import java.util.Optional;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.TrustChainCache;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@ActiveProfiles({"h2-test", "dev", "openid-federation"})
public class TrustChainCacheTests {

  @Test
  public void testInMemoryCacheDisabled() throws Exception {
    TrustChainCache cache = new TrustChainCache(false, false, null); // cacheEnabled=false
    TrustChain chain = TrustChainTestFactory.createRpToTaChain();

    cache.put("https://rp.example", chain);
    Optional<TrustChain> cached = cache.get("https://rp.example");

    assertTrue(cached.isEmpty());
  }

  @Test
  public void testInMemoryCacheStoresAndReads() throws Exception {
    TrustChainCache cache = new TrustChainCache(true, false, null); // cacheEnabled=true, redis=false

    TrustChain chain = TrustChainTestFactory.createRpToTaChain();

    cache.put("https://rp.example", chain);
    Optional<TrustChain> cached = cache.get("https://rp.example");

    assertTrue(!cached.isEmpty());
    // Verify exp of the trust chain has a value in the future
    assertTrue(cached.get().resolveExpirationTime().after(new Date()));
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testRedisCacheStoresAndRead() throws Exception {
    RedisTemplate<String, TrustChain> redisTemplate = mock(RedisTemplate.class);
    ValueOperations<String, TrustChain> valueOps = mock(ValueOperations.class);
    when(redisTemplate.opsForValue()).thenReturn(valueOps);

    TrustChainCache cache = new TrustChainCache(true, true, redisTemplate); // cacheEnabled=true, redis=true
    TrustChain chain = TrustChainTestFactory.createRpToTaChain();

    cache.put("https://rp.example", chain);
    verify(valueOps).set(eq("https://rp.example"), eq(chain), any(Duration.class));

    when(valueOps.get("https://rp.example")).thenReturn(chain);

    Optional<TrustChain> cached = cache.get("https://rp.example");

    assertTrue(!cached.isEmpty());
    assertEquals(chain, cached.get());
  }
}
