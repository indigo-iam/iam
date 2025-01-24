package it.infn.mw.iam.core.jwt.signer;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;

import it.infn.mw.iam.core.jwt.encryption.JWTEncryptionAndDecryptionService;

/**
 * Creates a caching map of JOSE signers/validators and encrypters/decryptors keyed on the JWK Set
 * URI. Dynamically loads JWK Sets to create the services.
 */
@Service
public class JWKSetCacheService {

  /**
   * Logger for this class
   */
  private static final Logger logger = LoggerFactory.getLogger(JWKSetCacheService.class);

  private LoadingCache<String, JWTSigningAndValidationService> validators;
  private LoadingCache<String, JWTEncryptionAndDecryptionService> encrypters;

  public JWKSetCacheService() {
    this.validators = CacheBuilder.newBuilder()
      .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
      .maximumSize(100)
      .build(new JWKSetVerifierFetcher(HttpClientBuilder.create().useSystemProperties().build()));
    this.encrypters = CacheBuilder.newBuilder()
      .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
      .maximumSize(100)
      .build(new JWKSetEncryptorFetcher(HttpClientBuilder.create().useSystemProperties().build()));
  }

  /**
   * @param jwksUri
   * @return
   * @throws ExecutionException
   * @see com.google.common.cache.Cache#get(java.lang.Object)
   */
  public JWTSigningAndValidationService getValidator(String jwksUri) {
    try {
      return validators.get(jwksUri);
    } catch (UncheckedExecutionException | ExecutionException e) {
      logger.warn("Couldn't load JWK Set from " + jwksUri + ": " + e.getMessage());
      return null;
    }
  }

  public JWTEncryptionAndDecryptionService getEncrypter(String jwksUri) {
    try {
      return encrypters.get(jwksUri);
    } catch (UncheckedExecutionException | ExecutionException e) {
      logger.warn("Couldn't load JWK Set from " + jwksUri + ": " + e.getMessage());
      return null;
    }
  }

}
