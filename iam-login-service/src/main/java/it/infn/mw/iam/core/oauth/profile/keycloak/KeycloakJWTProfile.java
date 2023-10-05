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
package it.infn.mw.iam.core.oauth.profile.keycloak;

import it.infn.mw.iam.core.oauth.profile.IDTokenCustomizer;
import it.infn.mw.iam.core.oauth.profile.IntrospectionResultHelper;
import it.infn.mw.iam.core.oauth.profile.JWTAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.UserInfoHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamJWTProfile;

public class KeycloakJWTProfile extends IamJWTProfile {

  public static final String PROFILE_VERSION = "1.0";
  public static final String PROFILE_NAME = "Keycloak JWT profile " + PROFILE_VERSION;

  public KeycloakJWTProfile(JWTAccessTokenBuilder accessTokenBuilder,
      IDTokenCustomizer idTokenBuilder, UserInfoHelper userInfoHelper,
      IntrospectionResultHelper introspectionHelper) {

    super(accessTokenBuilder, idTokenBuilder, userInfoHelper, introspectionHelper);
  }

  @Override
  public String name() {
    return PROFILE_NAME;
  }

}
