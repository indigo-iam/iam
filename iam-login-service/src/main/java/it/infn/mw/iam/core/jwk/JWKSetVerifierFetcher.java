package it.infn.mw.iam.core.jwk;

import org.apache.http.client.HttpClient;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.google.common.cache.CacheLoader;
import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.core.jwt.signer.DefaultJWTSigningAndValidationService;
import it.infn.mw.iam.core.jwt.signer.JWTSigningAndValidationService;

public class JWKSetVerifierFetcher extends CacheLoader<String, JWTSigningAndValidationService> {

  private RestTemplate restTemplate;

  JWKSetVerifierFetcher(HttpClient httpClient) {
      this.restTemplate = new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient));
  }

  @Override
  public JWTSigningAndValidationService load(String key) throws Exception {
      String jsonString = restTemplate.getForObject(key, String.class);
      JWKSet jwkSet = JWKSet.parse(jsonString);
      JWKSetKeyStore keyStore = new JWKSetKeyStore(jwkSet);
      return new DefaultJWTSigningAndValidationService(keyStore);
  }

}
