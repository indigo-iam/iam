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

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import static it.infn.mw.iam.core.oauth.IamOAuth2RequestFactory.RESOURCE;

// This is the org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter
// class where the OAuth2Authentication request is created without the _resource_ parameter,
// if it was not indicated in the token request
@SuppressWarnings("deprecation")
public class IamAuthorizationCodeTokenGranter extends AbstractTokenGranter {

  private static final String GRANT_TYPE = "authorization_code";

  private final AuthorizationCodeServices authorizationCodeServices;

  public IamAuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
      AuthorizationCodeServices authorizationCodeServices,
      ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
    super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
    this.authorizationCodeServices = authorizationCodeServices;
  }

  @Override
  protected OAuth2Authentication getOAuth2Authentication(ClientDetails client,
      TokenRequest tokenRequest) {

    Map<String, String> parameters = tokenRequest.getRequestParameters();
    String authorizationCode = parameters.get("code");
    String redirectUri = parameters.get(OAuth2Utils.REDIRECT_URI);

    if (authorizationCode == null) {
      throw new InvalidRequestException("An authorization code must be supplied.");
    }

    OAuth2Authentication storedAuth =
        authorizationCodeServices.consumeAuthorizationCode(authorizationCode);
    if (storedAuth == null) {
      throw new InvalidGrantException("Invalid authorization code");
    }

    OAuth2Request pendingOAuth2Request = storedAuth.getOAuth2Request();
    String redirectUriApprovalParameter =
        pendingOAuth2Request.getRequestParameters().get(OAuth2Utils.REDIRECT_URI);

    if ((redirectUri != null || redirectUriApprovalParameter != null)
        && !pendingOAuth2Request.getRedirectUri().equals(redirectUri)) {
      throw new RedirectMismatchException("Redirect URI mismatch.");
    }

    String pendingClientId = pendingOAuth2Request.getClientId();
    String clientId = tokenRequest.getClientId();
    if (clientId != null && !clientId.equals(pendingClientId)) {
      throw new InvalidClientException("Client ID mismatch");
    }

    Map<String, String> combinedParameters =
        new HashMap<String, String>(pendingOAuth2Request.getRequestParameters());
    combinedParameters.putAll(parameters);

    if (combinedParameters.containsKey(RESOURCE) && !parameters.containsKey(RESOURCE)) {
      combinedParameters.remove(RESOURCE);
    }

    OAuth2Request finalStoredOAuth2Request =
        pendingOAuth2Request.createOAuth2Request(combinedParameters);

    Authentication userAuth = storedAuth.getUserAuthentication();

    return new OAuth2Authentication(finalStoredOAuth2Request, userAuth);

  }

}
