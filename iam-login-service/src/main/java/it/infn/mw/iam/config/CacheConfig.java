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

import org.springframework.boot.autoconfigure.cache.RedisCacheManagerBuilderCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.cache.support.NoOpCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;

import it.infn.mw.iam.core.oauth.scope.matchers.DefaultScopeMatcherRegistry;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;

@Configuration
public class CacheConfig {

  @Bean
  @ConditionalOnExpression("${cache.enabled} == false")
  CacheManager fakeCacheManager(CacheProperties props) {
    return new NoOpCacheManager();
  }

  @Bean
  @ConditionalOnExpression("${cache.enabled} == true and ${cache.redis.enabled} == false")
  CacheManager localCacheManager(CacheProperties props) {
    return new ConcurrentMapCacheManager(IamWellKnownInfoProvider.CACHE_KEY,
        DefaultScopeMatcherRegistry.SCOPE_CACHE_KEY);
  }

  @Bean
  @ConditionalOnExpression("${cache.enabled} == true and ${cache.redis.enabled} == true")
  RedisCacheManagerBuilderCustomizer redisCacheManagerBuilderCustomizer() {
    return builder -> builder
      .withCacheConfiguration(IamWellKnownInfoProvider.CACHE_KEY,
          RedisCacheConfiguration.defaultCacheConfig())
      .withCacheConfiguration(DefaultScopeMatcherRegistry.SCOPE_CACHE_KEY,
          RedisCacheConfiguration.defaultCacheConfig());
  }

  @Bean
  @ConditionalOnExpression("${cache.enabled} == true and ${cache.redis.enabled} == true")
  RedisCacheConfiguration redisCacheConfiguration() {

    return RedisCacheConfiguration.defaultCacheConfig().disableCachingNullValues();
  }

}
