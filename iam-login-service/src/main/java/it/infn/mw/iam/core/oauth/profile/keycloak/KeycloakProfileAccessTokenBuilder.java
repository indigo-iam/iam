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

import static java.util.Objects.isNull;
import static java.util.stream.Collectors.joining;

import java.time.Instant;
import java.util.Date;
import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder;
import it.infn.mw.iam.persistence.repository.UserInfoAdapter;

@SuppressWarnings("deprecation")
public class KeycloakProfileAccessTokenBuilder extends BaseAccessTokenBuilder {

  public static final String PROFILE_VERSION = "1.0";

  final KeycloakGroupHelper groupHelper;

  public KeycloakProfileAccessTokenBuilder(IamProperties properties, KeycloakGroupHelper groupHelper) {
    super(properties);
    this.groupHelper = groupHelper;
  }


  @Override
  public JWTClaimsSet buildAccessToken(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication, UserInfo userInfo, Instant issueTime) {

    Builder builder = baseJWTSetup(token, authentication, userInfo, issueTime);

    builder.notBeforeTime(Date.from(issueTime));

    if (!token.getScope().isEmpty()) {
      builder.claim(SCOPE_CLAIM_NAME, token.getScope().stream().collect(joining(SPACE)));
    }

    if (!isNull(userInfo)) {
      Set<String> groupNames =
          groupHelper.resolveGroupNames(((UserInfoAdapter) userInfo).getUserinfo());

      if (!groupNames.isEmpty()) {
        builder.claim(KeycloakGroupHelper.KEYCLOAK_ROLES_CLAIM, groupNames);
      }
    }

    return builder.build();
  }

}
