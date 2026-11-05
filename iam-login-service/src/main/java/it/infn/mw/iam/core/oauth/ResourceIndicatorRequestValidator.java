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

import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenRequest;

/**
 * Adds resource indicator (RFC 8707) validation to authorization requests.
 *
 * The authorization endpoint calls this after resolving the client redirect URI, so a failure is
 * redirected to the client as an <code>invalid_target</code> error. Token requests are validated
 * when they are created by {@link IamOAuth2RequestFactory}.
 */
@SuppressWarnings("deprecation")
public class ResourceIndicatorRequestValidator implements OAuth2RequestValidator {

  private final OAuth2RequestValidator delegate;
  private final AudienceRequestValidator audienceRequestValidator;

  public ResourceIndicatorRequestValidator(OAuth2RequestValidator delegate,
      AudienceRequestValidator audienceRequestValidator) {
    this.delegate = delegate;
    this.audienceRequestValidator = audienceRequestValidator;
  }

  @Override
  public void validateScope(AuthorizationRequest authorizationRequest, ClientDetails client) {
    delegate.validateScope(authorizationRequest, client);
    audienceRequestValidator.validateResourceRequest(authorizationRequest.getRequestParameters());
  }

  @Override
  public void validateScope(TokenRequest tokenRequest, ClientDetails client) {
    delegate.validateScope(tokenRequest, client);
  }
}
