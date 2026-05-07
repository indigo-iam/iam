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
package it.infn.mw.iam.core.oauth.granters;

import java.util.HashSet;
import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;

import com.google.common.collect.Sets;

@SuppressWarnings("deprecation")
public class ChainedTokenGranter extends AbstractTokenGranter {

  public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant_type:redelegate";

  private final OAuth2TokenEntityService tokenServices;

  public ChainedTokenGranter(OAuth2TokenEntityService tokenServices,
      ClientDetailsEntityService clientDetailsService, OAuth2RequestFactory requestFactory) {
    super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
    this.tokenServices = tokenServices;
  }

  @Override
  public OAuth2TokenEntityService getTokenServices() {
    return tokenServices;
  }

  @Override
  protected OAuth2Authentication getOAuth2Authentication(ClientDetails client,
      TokenRequest tokenRequest) throws AuthenticationException, InvalidTokenException {

    String incomingTokenValue = tokenRequest.getRequestParameters().get("token");
    OAuth2AccessTokenEntity incomingToken = tokenServices.readAccessToken(incomingTokenValue);

    // check for scoping in the request, can't up-scope with a chained request
    Set<String> approvedScopes = incomingToken.getScope();
    Set<String> requestedScopes = tokenRequest.getScope();

    if (requestedScopes == null) {
      requestedScopes = new HashSet<>();
    }
    if (requestedScopes.isEmpty()) {
      tokenRequest.setScope(approvedScopes);
    } else if (approvedScopes.containsAll(requestedScopes)) {
      tokenRequest.setScope(Sets.intersection(requestedScopes, approvedScopes));
    } else {
      throw new InvalidScopeException("Invalid scope requested in chained request", approvedScopes);
    }

    return new OAuth2Authentication(getRequestFactory().createOAuth2Request(client, tokenRequest),
        incomingToken.getAuthenticationHolder().getAuthentication().getUserAuthentication());
  }
}
