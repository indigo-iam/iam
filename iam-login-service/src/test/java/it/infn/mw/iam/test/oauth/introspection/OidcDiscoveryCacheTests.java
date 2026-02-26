package it.infn.mw.iam.test.oauth.introspection;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.config.TaskConfig;
import it.infn.mw.iam.core.oauth.discovery.DefaultOidcDiscoveryService;

@SpringBootTest
@EnableCaching
@ActiveProfiles({"h2-test", "dev"})
class OidcDiscoveryCacheTests {

  @Autowired
  private DefaultOidcDiscoveryService discoveryService;

  @Autowired
  private TaskConfig taskConfig;

  @MockBean
  private RestTemplate restTemplate;

  @Autowired
  private CacheManager cacheManager;

  private static final String REMOTE_ISSUER = "https://example.com";
  private static final String URL = REMOTE_ISSUER + "/.well-known/openid-configuration";

  @BeforeEach
  void clearCache() {
    cacheManager.getCache(DefaultOidcDiscoveryService.CACHE_NAME).clear();
    assertNull(cacheManager.getCache(DefaultOidcDiscoveryService.CACHE_NAME).get(REMOTE_ISSUER));
  }

  @Test
  void testOidcDiscoveryCacheWorks() {

    JsonNode json = new ObjectMapper().createObjectNode().put("issuer", REMOTE_ISSUER);

    when(restTemplate.getForEntity(URL, JsonNode.class)).thenReturn(ResponseEntity.ok(json));

    discoveryService.getDiscoveryDocument(REMOTE_ISSUER, restTemplate);
    discoveryService.getDiscoveryDocument(REMOTE_ISSUER, restTemplate);

    verify(restTemplate, times(1)).getForEntity(URL, JsonNode.class);
    assertNotNull(cacheManager.getCache(DefaultOidcDiscoveryService.CACHE_NAME).get(REMOTE_ISSUER));
  }

  @Test
  void testOidcDiscoveryCacheEviction() throws Exception {

    JsonNode json = new ObjectMapper().createObjectNode().put("issuer", REMOTE_ISSUER);

    when(restTemplate.getForEntity(URL, JsonNode.class)).thenReturn(ResponseEntity.ok(json));

    discoveryService.getDiscoveryDocument(REMOTE_ISSUER, restTemplate);
    assertNotNull(cacheManager.getCache(DefaultOidcDiscoveryService.CACHE_NAME).get(REMOTE_ISSUER));

    taskConfig.logOidcDiscoveryCacheEviction();
    assertNull(cacheManager.getCache(DefaultOidcDiscoveryService.CACHE_NAME).get(REMOTE_ISSUER));

  }
}
