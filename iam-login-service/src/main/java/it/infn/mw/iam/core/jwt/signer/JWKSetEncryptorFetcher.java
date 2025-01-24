package it.infn.mw.iam.core.jwt.signer;

import org.apache.http.client.HttpClient;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.google.common.cache.CacheLoader;
import com.google.gson.JsonParseException;
import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.core.jwk.JWKSetKeyStore;
import it.infn.mw.iam.core.jwt.encryption.DefaultJWTEncryptionAndDecryptionService;
import it.infn.mw.iam.core.jwt.encryption.JWTEncryptionAndDecryptionService;

class JWKSetEncryptorFetcher extends CacheLoader<String, JWTEncryptionAndDecryptionService> {
    private HttpComponentsClientHttpRequestFactory httpFactory;
    private RestTemplate restTemplate;

    public JWKSetEncryptorFetcher(HttpClient httpClient) {
        this.httpFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        this.restTemplate = new RestTemplate(httpFactory);
    }

    /* (non-Javadoc)
     * @see com.google.common.cache.CacheLoader#load(java.lang.Object)
     */
    @Override
    public JWTEncryptionAndDecryptionService load(String key) throws Exception {
        try {
            String jsonString = restTemplate.getForObject(key, String.class);
            JWKSet jwkSet = JWKSet.parse(jsonString);

            JWKSetKeyStore keyStore = new JWKSetKeyStore(jwkSet);

            JWTEncryptionAndDecryptionService service = new DefaultJWTEncryptionAndDecryptionService(keyStore);

            return service;
        } catch (JsonParseException | RestClientException e) {
            throw new IllegalArgumentException("Unable to load JWK Set");
        }
    }
}