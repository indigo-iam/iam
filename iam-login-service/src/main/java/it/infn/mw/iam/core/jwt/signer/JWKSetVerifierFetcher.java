package it.infn.mw.iam.core.jwt.signer;

import org.apache.http.client.HttpClient;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.google.common.cache.CacheLoader;
import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.core.jwk.JWKSetKeyStore;

public class JWKSetVerifierFetcher extends CacheLoader<String, JWTSigningAndValidationService> {
  private HttpComponentsClientHttpRequestFactory httpFactory;
  private RestTemplate restTemplate;

  JWKSetVerifierFetcher(HttpClient httpClient) {
    this.httpFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
    this.restTemplate = new RestTemplate(httpFactory);
  }

  /**
   * Load the JWK Set and build the appropriate signing service.
   */
  @Override
  public JWTSigningAndValidationService load(String key) throws Exception {
    String jsonString = restTemplate.getForObject(key, String.class);
    JWKSet jwkSet = JWKSet.parse(jsonString);

    JWKSetKeyStore keyStore = new JWKSetKeyStore(jwkSet);

    JWTSigningAndValidationService service = new DefaultJWTSigningAndValidationService(keyStore);

    return service;
  }

}
