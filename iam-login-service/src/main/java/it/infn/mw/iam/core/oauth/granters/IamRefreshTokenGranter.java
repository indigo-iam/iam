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

import static java.lang.String.format;

import java.util.Optional;

import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.AUPSignatureCheckService;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public class IamRefreshTokenGranter extends RefreshTokenGranter {

  private final OAuth2TokenEntityService tokenServices;
  private AUPSignatureCheckService signatureCheckService;
  private AccountUtils accountUtils;

  public IamRefreshTokenGranter(OAuth2TokenEntityService tokenServices,
      ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
    super(tokenServices, clientDetailsService, requestFactory);
    this.tokenServices = tokenServices;
  }

  @Override
  protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
    String refreshTokenValue = tokenRequest.getRequestParameters().get("refresh_token");
    OAuth2RefreshTokenEntity refreshToken = tokenServices.getRefreshToken(refreshTokenValue);

    Optional<IamAccount> user = accountUtils
      .getAuthenticatedUserAccount(refreshToken.getAuthenticationHolder().getUserAuth());

    if (user.isPresent() && signatureCheckService.needsAupSignature(user.get())) {
      throw new InvalidGrantException(
          format("User %s needs to sign AUP for this organization in order to proceed.",
              user.get().getUsername()));
    }

    return getTokenServices().refreshAccessToken(refreshTokenValue, tokenRequest);
  }

  public void setSignatureCheckService(AUPSignatureCheckService signatureCheckService) {
    this.signatureCheckService = signatureCheckService;
  }

  public void setAccountUtils(AccountUtils accountUtils) {
    this.accountUtils = accountUtils;
  }

}

