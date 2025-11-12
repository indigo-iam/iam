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
package it.infn.mw.iam.core.oauth.profile.common;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.core.oauth.profile.AccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.IDTokenCustomizer;
import it.infn.mw.iam.core.oauth.profile.IntrospectionResultHelper;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.RequestValidator;
import it.infn.mw.iam.core.oauth.profile.UserInfoHelper;

public abstract class BaseJWTProfile implements JWTProfile, RequestValidator {

  private final ScopeClaimTranslationService scopeClaimTranslationService;
  private final ClaimValueHelper claimValueHelper;
  private final AccessTokenBuilder accessTokenBuilder;
  private final IDTokenCustomizer idTokenCustomizer;
  private final UserInfoHelper userInfoHelper;
  private final IntrospectionResultHelper introspectionHelper;

  protected BaseJWTProfile(ScopeClaimTranslationService scopeClaimTranslationService,
      ClaimValueHelper claimValueHelper, AccessTokenBuilder accessTokenBuilder,
      IDTokenCustomizer idTokenCustomizer, UserInfoHelper userInfoHelper,
      IntrospectionResultHelper introspectionHelper) {

    this.scopeClaimTranslationService = scopeClaimTranslationService;
    this.claimValueHelper = claimValueHelper;
    this.accessTokenBuilder = accessTokenBuilder;
    this.idTokenCustomizer = idTokenCustomizer;
    this.userInfoHelper = userInfoHelper;
    this.introspectionHelper = introspectionHelper;
  }

  @Override
  public ScopeClaimTranslationService getScopeClaimTranslationService() {
    return scopeClaimTranslationService;
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
