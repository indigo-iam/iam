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
    return buildIdToken(OidcTestConfig.TEST_OIDC_ISSUER, clientId, sub, nonce);
  }

  public String buildIdToken(String issuer, String clientId, String sub, String nonce)
      throws JOSEException {
    IdTokenBuilder builder = new IdTokenBuilder(keyStore, signingAlgo);
    return builder.issuer(issuer).sub(sub).audience(clientId).nonce(nonce).build();
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
    return prepareTokenResponse(OidcTestConfig.TEST_OIDC_ISSUER, clientId, sub, nonce);
  }

  public String prepareTokenResponse(String issuer, String clientId, String sub, String nonce)
      throws JOSEException, JsonProcessingException {

    TokenResponse tokenResponse = new TokenResponse();
    tokenResponse.setAccessToken(UUID.randomUUID().toString());
    tokenResponse.setIdToken(buildIdToken(issuer, clientId, sub, nonce));

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
