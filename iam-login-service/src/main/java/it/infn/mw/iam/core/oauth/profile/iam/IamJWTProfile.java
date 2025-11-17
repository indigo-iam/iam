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
package it.infn.mw.iam.core.oauth.profile.iam;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;

import it.infn.mw.iam.core.oauth.profile.AccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.IDTokenCustomizer;
import it.infn.mw.iam.core.oauth.profile.IntrospectionResultHelper;
import it.infn.mw.iam.core.oauth.profile.UserInfoHelper;
import it.infn.mw.iam.core.oauth.profile.common.BaseJWTProfile;

public class IamJWTProfile extends BaseJWTProfile {

  public static final String PROFILE_NAME = "IAM JWT profile";

  public IamJWTProfile(ScopeClaimTranslationService scopeClaimTranslationService,
      ClaimValueHelper claimValueHelper, AccessTokenBuilder accessTokenBuilder,
      IDTokenCustomizer idTokenCustomizer, UserInfoHelper userInfoHelper,
      IntrospectionResultHelper introspectionHelper) {
    super(scopeClaimTranslationService, claimValueHelper, accessTokenBuilder, idTokenCustomizer,
        userInfoHelper, introspectionHelper);
  }

  @Override
  public String id() {
    return IamOidcScopes.IAM;
  }

  @Override
  public String name() {
    return PROFILE_NAME;
  }
}
