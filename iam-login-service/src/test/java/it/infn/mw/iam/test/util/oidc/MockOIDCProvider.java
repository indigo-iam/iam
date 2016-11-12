package it.infn.mw.iam.test.util.oidc;

import java.util.UUID;

import org.mitre.jose.keystore.JWKSetKeyStore;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;

import it.infn.mw.iam.authn.oidc.OidcClientError;
import it.infn.mw.iam.authn.oidc.OidcClientFilter.OidcProviderConfiguration;
import it.infn.mw.iam.authn.oidc.OidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.model.TokenEndpointErrorResponse;
import it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig;

public class MockOIDCProvider implements OidcTokenRequestor {

  private JWKSetKeyStore keyStore;
  private JWSAlgorithm signingAlgo = JWSAlgorithm.RS256;

  private final ObjectMapper mapper;

  private String lastTokenResponse;

  private OidcClientError clientError;


  public MockOIDCProvider(ObjectMapper mapper, JWKSetKeyStore keyStore) {
    this.keyStore = keyStore;
    this.mapper = mapper;
  }

  public String buildIdToken(String clientId, String sub, String nonce) throws JOSEException {
    IdTokenBuilder builder = new IdTokenBuilder(keyStore, signingAlgo);
    return builder.issuer(OidcTestConfig.TEST_OIDC_ISSUER)
      .sub(sub)
      .audience(clientId)
      .nonce(nonce)
      .build();
  }

  public String prepareErrorResponse(String error, String errorDescription)
      throws JsonProcessingException {

    TokenEndpointErrorResponse errorResponse = new TokenEndpointErrorResponse();
    errorResponse.setError(error);
    errorResponse.setErrorDescription(errorDescription);

    lastTokenResponse = mapper.writeValueAsString(errorResponse);

    return lastTokenResponse;
  }

  public void prepareError(String error, String errorDescription) {
    clientError = new OidcClientError("Token request error", error, errorDescription, null);
  }

  public String prepareTokenResponse(String clientId, String sub, String nonce)
      throws JOSEException, JsonProcessingException {

    TokenResponse tokenResponse = new TokenResponse();
    tokenResponse.setAccessToken(UUID.randomUUID().toString());
    tokenResponse.setIdToken(buildIdToken(clientId, sub, nonce));

    lastTokenResponse = mapper.writeValueAsString(tokenResponse);

    return lastTokenResponse;
  }

  @Override
  public String requestTokens(OidcProviderConfiguration conf,
      MultiValueMap<String, String> tokenRequestParams) throws OidcClientError {

    if (clientError != null) {
      // clean up for next calls
      OidcClientError clientErrorCopy = clientError;
      clientError = null;

      throw clientErrorCopy;
    }

    return lastTokenResponse;
  }

  public String getLastTokenResponse() {
    return lastTokenResponse;
  }

  public void setLastTokenResponse(String lastTokenResponse) {
    this.lastTokenResponse = lastTokenResponse;
  }

}
