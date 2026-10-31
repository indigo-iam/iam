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
package it.infn.mw.iam.api.tokens.service;

import java.util.Optional;

import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@Service
public class CachedRefreshTokenStore {

    public static final String CACHE_NAME = "RefreshTokenEntity";

    private final IamOAuthRefreshTokenRepository tokenRepository;

    private final CacheManager cacheManager;

    public CachedRefreshTokenStore(
            IamOAuthRefreshTokenRepository tokenRepository, CacheManager cacheManager) {

        this.tokenRepository = tokenRepository;
        this.cacheManager = cacheManager;
    }

    @CacheEvict(cacheNames = CACHE_NAME, key = "#token.value")
    public void delete(OAuth2RefreshTokenEntity token) {
        tokenRepository.delete(token);
    }

    @CacheEvict(cacheNames = CACHE_NAME, key = "#token.value")
    public OAuth2RefreshTokenEntity save(OAuth2RefreshTokenEntity token) {
        return tokenRepository.save(token);
    }

    @Cacheable(cacheNames = CACHE_NAME, key = "#token", unless = "#result == null")
    public Optional<OAuth2RefreshTokenEntity> getToken(String token) {
        return tokenRepository.findByTokenValue(token);
    }

    public void evictAll(Iterable<OAuth2RefreshTokenEntity> tokens) {
        Cache cache = cacheManager.getCache(CACHE_NAME);

        if (cache != null) {
            tokens.forEach(token -> cache.evictIfPresent(token.getValue()));
        }
    }

}
