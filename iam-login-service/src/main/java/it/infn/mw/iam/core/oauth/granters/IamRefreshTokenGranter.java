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

  public IamRefreshTokenGranter(OAuth2TokenEntityService tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
      super(tokenServices, clientDetailsService, requestFactory);
      this.tokenServices = tokenServices;
  }

  protected IamRefreshTokenGranter(OAuth2TokenEntityService tokenServices, ClientDetailsService clientDetailsService,
          OAuth2RequestFactory requestFactory, String grantType) {
      super(tokenServices, clientDetailsService, requestFactory, grantType);
      this.tokenServices = tokenServices;
  }

  @Override
  protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
      String refreshTokenValue = tokenRequest.getRequestParameters().get("refresh_token");
      OAuth2RefreshTokenEntity refreshToken = tokenServices.getRefreshToken(refreshTokenValue);

      Optional<IamAccount> user = accountUtils.getAuthenticatedUserAccount(refreshToken.getAuthenticationHolder().getUserAuth());
      
      if(user.isPresent() && signatureCheckService.needsAupSignature(user.get())) {
        throw new InvalidGrantException(
            format("User %s needs to sign AUP for this organization in order to proceed.",
                user.get().getUsername()));
      }

      return getTokenServices().refreshAccessToken(refreshTokenValue, tokenRequest);
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

