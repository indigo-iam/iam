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

import org.springframework.boot.autoconfigure.cache.RedisCacheManagerBuilderCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.cache.support.NoOpCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;

import com.github.benmanes.caffeine.cache.Caffeine;

import it.infn.mw.iam.authn.oidc.service.UserInfoFetcher;
import it.infn.mw.iam.core.jwk.IamJWTSigningService;
import it.infn.mw.iam.core.oauth.discovery.DefaultOidcDiscoveryService;
import it.infn.mw.iam.core.oauth.scope.matchers.DefaultScopeMatcherRegistry;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;

@Configuration
public class CacheConfig {

  private CacheProperties cacheProps;

  CacheConfig(CacheProperties cacheProps) {
    this.cacheProps = cacheProps;
  }

  @Bean
  @ConditionalOnExpression("${cache.enabled} == false")
  CacheManager fakeCacheManager() {
    return new NoOpCacheManager();
  }

  @Bean
  @ConditionalOnExpression("${cache.enabled} == true and ${cache.redis.enabled} == false")
  CacheManager localCacheManager() {
    CaffeineCacheManager cacheManager = new CaffeineCacheManager();

    cacheManager.registerCustomCache(IamWellKnownInfoProvider.CACHE_KEY,
        Caffeine.newBuilder().build());

    cacheManager.registerCustomCache(DefaultScopeMatcherRegistry.SCOPE_CACHE_KEY,
        Caffeine.newBuilder().build());

    cacheManager.registerCustomCache(DefaultOidcDiscoveryService.CACHE_NAME,
        Caffeine.newBuilder()
          .expireAfterWrite(Duration.ofSeconds(cacheProps.getOidcDiscoveryCleanupPeriodSecs()))
          .build());

    // The hardcoded TTL in MitreID was 1h
    cacheManager.registerCustomCache(UserInfoFetcher.USERINFO_CACHE_NAME,
        Caffeine.newBuilder().expireAfterWrite(Duration.ofSeconds(3600)).build());

    /* Access tokens by default expire in 1h */
    cacheManager.registerCustomCache(IamJWTSigningService.SIGNATURE_VALIDATION_CACHE,
        Caffeine.newBuilder().expireAfterWrite(Duration.ofSeconds(3600)).build());

    return cacheManager;
  }

  @Bean
  @ConditionalOnExpression("${cache.enabled} == true and ${cache.redis.enabled} == true")
  RedisCacheManagerBuilderCustomizer redisCacheManagerBuilderCustomizer() {

    RedisCacheConfiguration config =
        RedisCacheConfiguration.defaultCacheConfig().disableCachingNullValues();

    return builder -> builder.withCacheConfiguration(IamWellKnownInfoProvider.CACHE_KEY, config)
      .withCacheConfiguration(DefaultScopeMatcherRegistry.SCOPE_CACHE_KEY, config)
      .withCacheConfiguration(DefaultOidcDiscoveryService.CACHE_NAME,
          config.entryTtl(Duration.ofSeconds(cacheProps.getOidcDiscoveryCleanupPeriodSecs())))
      .withCacheConfiguration(UserInfoFetcher.USERINFO_CACHE_NAME,
          config.entryTtl(Duration.ofSeconds(3600)))
      .withCacheConfiguration(IamJWTSigningService.SIGNATURE_VALIDATION_CACHE,
          config.entryTtl(Duration.ofSeconds(3600)));
  }

}
