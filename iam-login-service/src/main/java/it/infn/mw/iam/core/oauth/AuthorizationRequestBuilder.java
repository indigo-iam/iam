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
package it.infn.mw.iam.core.oauth;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetailsService;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Joiner;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.core.oidc.ConnectRequestParameters;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;

@SuppressWarnings("deprecation")
public class AuthorizationRequestBuilder {

  private static final Logger LOG = LoggerFactory.getLogger(AuthorizationRequestBuilder.class);

  private final ScopeFilter scopeFilter;
  private final Joiner joiner = Joiner.on(' ');
  private final ClientDetailsService clientDetailsService;
  private final RequestObjectProcessor requestObjectProcessor;
  private final JsonParser parser = new JsonParser();

  AuthorizationRequestBuilder(ClientDetailsService clientDetailsService, ScopeFilter scopeFilter,
      RequestObjectProcessor requestObjectProcessor) {
    this.clientDetailsService = clientDetailsService;
    this.scopeFilter = scopeFilter;
    this.requestObjectProcessor = requestObjectProcessor;
  }

  void filterRequestedScopes(Map<String, String> inputParams, Authentication authn,
      AuthorizationRequest authzRequest) {
    if (authn == null || authn instanceof AnonymousAuthenticationToken) {
      return;
    }

    Set<String> requestedScopes =
        OAuth2Utils.parseParameterList(inputParams.get(OAuth2Utils.SCOPE));

    // scopes are filtered also here to avoid authorizing them on the consent page
    inputParams.put(OAuth2Utils.SCOPE,
        joiner.join(scopeFilter.filterScopes(requestedScopes, authn, authzRequest.getClientId())));
  }

  AuthorizationRequest build(Map<String, String> inputParams) {
    return new AuthorizationRequest(inputParams, Collections.emptyMap(),
        inputParams.get(OAuth2Utils.CLIENT_ID),
        OAuth2Utils.parseParameterList(inputParams.get(OAuth2Utils.SCOPE)), null, null, false,
        inputParams.get(OAuth2Utils.STATE), inputParams.get(OAuth2Utils.REDIRECT_URI),
        OAuth2Utils.parseParameterList(inputParams.get(OAuth2Utils.RESPONSE_TYPE)));
  }

  void addExtensions(Map<String, String> inputParams, AuthorizationRequest authzRequest) {
    copyExtension(inputParams, authzRequest, ConnectRequestParameters.PROMPT);
    copyExtension(inputParams, authzRequest, ConnectRequestParameters.NONCE);
    copyExtension(inputParams, authzRequest, ConnectRequestParameters.MAX_AGE);
    copyExtension(inputParams, authzRequest, ConnectRequestParameters.LOGIN_HINT);
    copyExtension(inputParams, authzRequest, ConnectRequestParameters.AUD);
    addClaimsExtension(inputParams, authzRequest);
    addPkceExtensions(inputParams, authzRequest);
    addRequestObjectExtension(inputParams, authzRequest);
  }

  void applyClientDefaults(AuthorizationRequest authzRequest) {
    if (authzRequest.getClientId() == null) {
      return;
    }

    try {
      ClientDetailsEntity client = (ClientDetailsEntity) clientDetailsService
        .loadClientByClientId(authzRequest.getClientId());

      applyDefaultScopes(authzRequest, client);
      applyDefaultMaxAge(authzRequest, client);

    } catch (OAuth2Exception e) {
      LOG.error("Caught OAuth2 exception trying to test client scopes and max age:", e);
    }
  }

  void addAuthenticationMethodReferences(Authentication authn, AuthorizationRequest authzRequest) {
    if (authn instanceof ExtendedAuthenticationToken extendedToken) {
      processToken(extendedToken.getAuthenticationMethodReferences(), authzRequest);
      return;
    }

    if (authn instanceof AbstractExternalAuthenticationToken<?> externalToken) {
      processToken(externalToken.getAuthenticationMethodReferences(), authzRequest);
    }
  }

  private void copyExtension(Map<String, String> inputParams, AuthorizationRequest authzRequest,
      String key) {
    if (inputParams.containsKey(key)) {
      authzRequest.getExtensions().put(key, inputParams.get(key));
    }
  }

  private void addClaimsExtension(Map<String, String> inputParams,
      AuthorizationRequest authzRequest) {
    if (!inputParams.containsKey(ConnectRequestParameters.CLAIMS)) {
      return;
    }

    JsonObject claimsRequest = parseClaimRequest(inputParams.get(ConnectRequestParameters.CLAIMS));
    if (claimsRequest != null) {
      authzRequest.getExtensions().put(ConnectRequestParameters.CLAIMS, claimsRequest.toString());
    }
  }

  private void addPkceExtensions(Map<String, String> inputParams,
      AuthorizationRequest authzRequest) {
    if (!inputParams.containsKey(ConnectRequestParameters.CODE_CHALLENGE)) {
      return;
    }

    authzRequest.getExtensions()
      .put(ConnectRequestParameters.CODE_CHALLENGE,
          inputParams.get(ConnectRequestParameters.CODE_CHALLENGE));
    authzRequest.getExtensions()
      .put(ConnectRequestParameters.CODE_CHALLENGE_METHOD, inputParams
        .getOrDefault(ConnectRequestParameters.CODE_CHALLENGE_METHOD, PKCEAlgorithm.S256.name()));
  }

  private void addRequestObjectExtension(Map<String, String> inputParams,
      AuthorizationRequest authzRequest) {
    if (inputParams.containsKey(ConnectRequestParameters.REQUEST)) {
      authzRequest.getExtensions()
        .put(ConnectRequestParameters.REQUEST, inputParams.get(ConnectRequestParameters.REQUEST));
      requestObjectProcessor.processRequestObject(inputParams.get(ConnectRequestParameters.REQUEST),
          authzRequest);
    }
  }

  private void applyDefaultScopes(AuthorizationRequest authzRequest, ClientDetailsEntity client) {
    if (authzRequest.getScope() == null || authzRequest.getScope().isEmpty()) {
      authzRequest.setScope(client.getScope());
    }
  }

  private void applyDefaultMaxAge(AuthorizationRequest authzRequest, ClientDetailsEntity client) {
    if (authzRequest.getExtensions().get(ConnectRequestParameters.MAX_AGE) == null
        && client.getDefaultMaxAge() != null) {
      authzRequest.getExtensions()
        .put(ConnectRequestParameters.MAX_AGE, client.getDefaultMaxAge().toString());
    }
  }

  private JsonObject parseClaimRequest(String claimRequestString) {
    if (claimRequestString == null || claimRequestString.isEmpty()) {
      return null;
    }

    JsonElement el = parser.parse(claimRequestString);
    if (el != null && el.isJsonObject()) {
      return el.getAsJsonObject();
    }

    return null;
  }

  private void processToken(Set<IamAuthenticationMethodReference> amrSet,
      AuthorizationRequest authzRequest) {
    try {
      authzRequest.getExtensions().put("amr", parseAuthenticationMethodReferences(amrSet));
    } catch (JsonProcessingException e) {
      LOG.error("Failed to convert amr set to JSON array", e);
    }
  }

  private String parseAuthenticationMethodReferences(Set<IamAuthenticationMethodReference> amrSet)
      throws JsonProcessingException {
    List<String> amrList = new ArrayList<>();
    for (IamAuthenticationMethodReference amr : amrSet) {
      amrList.add(amr.getName());
    }

    ObjectMapper objectMapper = new ObjectMapper();
    return objectMapper.writeValueAsString(amrList);
  }
}
