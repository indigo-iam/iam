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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.AUPSignatureCheckService;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public class IamResourceOwnerPasswordTokenGranter extends ResourceOwnerPasswordTokenGranter {

  private AUPSignatureCheckService signatureCheckService;
  private AccountUtils accountUtils;

  public IamResourceOwnerPasswordTokenGranter(AuthenticationManager authenticationManager,
      AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService,
      OAuth2RequestFactory requestFactory) {
    super(authenticationManager, tokenServices, clientDetailsService, requestFactory);
  }

  public IamResourceOwnerPasswordTokenGranter(AuthenticationManager authenticationManager,
      AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService,
      OAuth2RequestFactory requestFactory, String grantType) {
    super(authenticationManager, tokenServices, clientDetailsService, requestFactory, grantType);
  }

  @Override
  protected OAuth2Authentication getOAuth2Authentication(ClientDetails client,
      TokenRequest tokenRequest) {

    OAuth2Authentication auth = super.getOAuth2Authentication(client, tokenRequest);
    Optional<IamAccount> user = accountUtils.getAuthenticatedUserAccount(auth);

    if (user.isPresent() && signatureCheckService.needsAupSignature(user.get())) {
      throw new InvalidGrantException(
          format("User %s needs to sign AUP for this organization in order to proceed.",
              user.get().getUsername()));
    }

    return auth;
  }

  public AUPSignatureCheckService getSignatureCheckService() {
    return signatureCheckService;
  }

  public void setSignatureCheckService(AUPSignatureCheckService signatureCheckService) {
    this.signatureCheckService = signatureCheckService;
  }

  public AccountUtils getAccountUtils() {
    return accountUtils;
  }

  public void setAccountUtils(AccountUtils accountUtils) {
    this.accountUtils = accountUtils;
  }

}
