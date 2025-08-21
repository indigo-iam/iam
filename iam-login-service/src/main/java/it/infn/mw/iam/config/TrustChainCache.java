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
package it.infn.mw.iam.config;

import java.time.Duration;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

@Component
public class TrustChainCache {

  private final boolean cacheEnabled;
  private final boolean redisEnabled;
  private final RedisTemplate<String, TrustChain> redisTemplate;
  private final Map<String, CachedTrustChain> inMemoryCache = new ConcurrentHashMap<>();

  public TrustChainCache(@Value("${cache.enabled}") boolean cacheEnabled,
      @Value("${cache.redis.enabled}") boolean redisEnabled,
      @Autowired(required = false) RedisTemplate<String, TrustChain> redisTemplate) {
    this.cacheEnabled = cacheEnabled;
    this.redisEnabled = redisEnabled;
    this.redisTemplate = redisTemplate;
  }

  public Optional<TrustChain> get(String entityId) {
    if (!cacheEnabled) {
      return Optional.empty();
    }
    if (redisEnabled) {
      TrustChain cached = redisTemplate.opsForValue().get(entityId);
      return Optional.ofNullable(cached);
    } else {
      CachedTrustChain cached = inMemoryCache.get(entityId);
      if (cached != null && !cached.isExpired()) {
        return Optional.of(cached.getTrustChain());
      }
      return Optional.empty();
    }
  }

  public void put(String entityId, TrustChain trustChain) {
    Duration ttl = resolveTTL(trustChain);
    if (!cacheEnabled) {
      return;
    }
    if (redisEnabled) {
      // Save on Redis cache with dynamic TTL
      redisTemplate.opsForValue().set(entityId, trustChain, ttl);
    } else {
      // Save on in-memory cache with dynamic TTL
      inMemoryCache.put(entityId, new CachedTrustChain(trustChain, ttl));
    }
  }

  private Duration resolveTTL(TrustChain trustChain) {
    Date expirationDate = trustChain.resolveExpirationTime();
    long expirationTimeMillis = expirationDate.getTime();
    long now = System.currentTimeMillis();
    long ttlMillis = Math.max(expirationTimeMillis - now, 0);
    return Duration.ofMillis(ttlMillis);
  }

  // Wrapper for in-memory cache with expiration
  private static class CachedTrustChain {
    private final TrustChain trustChain;
    private final long expiryTimeMillis;

    CachedTrustChain(TrustChain trustChain, Duration ttl) {
      this.trustChain = trustChain;
      this.expiryTimeMillis = System.currentTimeMillis() + ttl.toMillis();
    }

    boolean isExpired() {
      return System.currentTimeMillis() > expiryTimeMillis;
    }

    TrustChain getTrustChain() {
      return trustChain;
    }
  }
}
