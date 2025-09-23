package it.infn.mw.iam.core.oauth.profile.common;

import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.IDTokenCustomizer;
import it.infn.mw.iam.core.oauth.profile.IntrospectionResultHelper;
import it.infn.mw.iam.core.oauth.profile.AccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.RequestValidator;
import it.infn.mw.iam.core.oauth.profile.UserInfoHelper;

public abstract class BaseJWTProfile implements JWTProfile, RequestValidator {

  private final ClaimValueHelper claimValueHelper;
  private final AccessTokenBuilder accessTokenBuilder;
  private final IDTokenCustomizer idTokenCustomizer;
  private final UserInfoHelper userInfoHelper;
  private final IntrospectionResultHelper introspectionHelper;

  public BaseJWTProfile(ClaimValueHelper claimValueHelper, AccessTokenBuilder accessTokenBuilder,
      IDTokenCustomizer idTokenCustomizer, UserInfoHelper userInfoHelper,
      IntrospectionResultHelper introspectionHelper) {

    this.claimValueHelper = claimValueHelper;
    this.accessTokenBuilder = accessTokenBuilder;
    this.idTokenCustomizer = idTokenCustomizer;
    this.userInfoHelper = userInfoHelper;
    this.introspectionHelper = introspectionHelper;
  }

  @Override
  public ClaimValueHelper getClaimValueHelper() {
    return claimValueHelper;
  }

  @Override
  public AccessTokenBuilder getAccessTokenBuilder() {
    return accessTokenBuilder;
  }

  @Override
  public IDTokenCustomizer getIDTokenCustomizer() {
    return idTokenCustomizer;
  }

  @Override
  public IntrospectionResultHelper getIntrospectionResultHelper() {
    return introspectionHelper;
  }

  @Override
  public UserInfoHelper getUserinfoHelper() {
    return userInfoHelper;
  }

  @SuppressWarnings("deprecation") 
  @Override
  public void validateRequest(OAuth2Request request) {
    // nothing to do
  }

  @Override
  public RequestValidator getRequestValidator() {
    return this;
  }

}
