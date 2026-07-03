package it.infn.mw.iam.test.ext_authn.oidc;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.cache.support.NoOpCacheManager;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadata;
import it.infn.mw.iam.authn.oidc.PendingOIDCAuthenticationToken;
import it.infn.mw.iam.authn.oidc.service.UserInfoFetcher;

public class UserInfoFetcherCacheTests {

  private static final String REMOTE_ISSUER = "https://example.com";
  private static final String AUTHORIZE_ENDPOINT = REMOTE_ISSUER + "/authorize";
  private static final String TOKEN_ENDPOINT = REMOTE_ISSUER + "/token";
  private static final String JWKS_ENDPOINT = REMOTE_ISSUER + "/jwks";
  private static final String USERINFO_URL = REMOTE_ISSUER + "/userinfo";

  private static final String SUB = "test-subject";

  private PendingOIDCAuthenticationToken buildToken() {

    ObjectNode raw = new ObjectMapper().createObjectNode();
    OIDCProviderMetadata metadata = new OIDCProviderMetadata(REMOTE_ISSUER, AUTHORIZE_ENDPOINT,
        TOKEN_ENDPOINT, JWKS_ENDPOINT, USERINFO_URL, raw);

    return new PendingOIDCAuthenticationToken(SUB, REMOTE_ISSUER, metadata, null, null);
  }

  @Nested
  @SpringBootTest(properties = {"cache.enabled=true", "cache.redis.enabled=false"})
  @EnableCaching
  class InMemoryCacheTest {

    @SpyBean
    private UserInfoFetcher userInfoFetcher;

    @Autowired
    private CacheManager cacheManager;

    @BeforeEach
    void clearCache() {
      cacheManager.getCache(UserInfoFetcher.USERINFO_CACHE_NAME).clear();
    }

    @Test
    void testUserInfoFetcherCacheWorks() {

      PendingOIDCAuthenticationToken token = buildToken();

      String userInfoJson = String.format("{\"sub\":\"%s\"}", SUB);
      doReturn(userInfoJson).when(userInfoFetcher)
        .fetchUserInfo(any(RestTemplate.class), anyString());

      userInfoFetcher.loadUserInfo(token);
      userInfoFetcher.loadUserInfo(token);

      verify(userInfoFetcher, times(1)).fetchUserInfo(any(RestTemplate.class), anyString());

      assertNotNull(cacheManager.getCache(UserInfoFetcher.USERINFO_CACHE_NAME).get(SUB));
      assertTrue(cacheManager instanceof CaffeineCacheManager);
    }
  }

  @Nested
  @SpringBootTest(properties = {"cache.enabled=true", "cache.redis.enabled=true"})
  @EnableCaching
  class RedisCacheTest {

    @Autowired
    CacheManager cacheManager;

    @Test
    void testUseRedisCacheManager() {
      assertTrue(cacheManager instanceof RedisCacheManager);
    }
  }

  @Nested
  @SpringBootTest(properties = {"cache.enabled=false"})
  @EnableCaching
  class NoCacheTest {

    @SpyBean
    private UserInfoFetcher userInfoFetcher;

    @Autowired
    private CacheManager cacheManager;

    @BeforeEach
    void clearCache() {
      cacheManager.getCache(UserInfoFetcher.USERINFO_CACHE_NAME).clear();
    }

    @Test
    void testOidcDiscoveryNotCached() {

      PendingOIDCAuthenticationToken token = buildToken();

      String userInfoJson = String.format("{\"sub\":\"%s\"}", SUB);
      doReturn(userInfoJson).when(userInfoFetcher)
        .fetchUserInfo(any(RestTemplate.class), anyString());

      userInfoFetcher.loadUserInfo(token);
      userInfoFetcher.loadUserInfo(token);

      verify(userInfoFetcher, times(2)).fetchUserInfo(any(RestTemplate.class), anyString());

      assertNull(cacheManager.getCache(UserInfoFetcher.USERINFO_CACHE_NAME).get(SUB));
      assertTrue(cacheManager instanceof NoOpCacheManager);

    }

  }
}
