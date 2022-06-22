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
package it.infn.mw.iam.core.oauth.profile.aarc;

import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.core.oauth.profile.IDTokenCustomizer;
import it.infn.mw.iam.core.oauth.profile.IntrospectionResultHelper;
import it.infn.mw.iam.core.oauth.profile.JWTAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.RequestValidator;
import it.infn.mw.iam.core.oauth.profile.UserInfoHelper;

@SuppressWarnings("deprecation")
public class AarcJWTProfile implements JWTProfile, RequestValidator {

  public static final String PROFILE_NAME = "AARC JWT profile";

  private final JWTAccessTokenBuilder accessTokenBuilder;
  private final IDTokenCustomizer idTokenCustomizer;
  private final UserInfoHelper userInfoHelper;
  private final IntrospectionResultHelper introspectionHelper;

  public AarcJWTProfile(JWTAccessTokenBuilder accessTokenBuilder, IDTokenCustomizer idTokenBuilder,
      UserInfoHelper userInfoHelper, IntrospectionResultHelper introspectionHelper) {
    this.accessTokenBuilder = accessTokenBuilder;
    this.idTokenCustomizer = idTokenBuilder;
    this.userInfoHelper = userInfoHelper;
    this.introspectionHelper = introspectionHelper;
  }

  @Override
  public void validateRequest(OAuth2Request request) {
    // no validation
  }

  @Override
  public String name() {
    return PROFILE_NAME;
  }

  @Override
  public JWTAccessTokenBuilder getAccessTokenBuilder() {
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

  @Override
  public RequestValidator getRequestValidator() {
    return this;
  }

}
