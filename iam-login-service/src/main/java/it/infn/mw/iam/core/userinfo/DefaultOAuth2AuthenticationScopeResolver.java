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
package it.infn.mw.iam.core.userinfo;

import static java.util.Objects.isNull;

import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.repository.OAuth2TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;

@Component
@SuppressWarnings("deprecation")
public class DefaultOAuth2AuthenticationScopeResolver implements OAuth2AuthenticationScopeResolver {

  private final OAuth2TokenRepository tokenRepo;

  @Autowired
  public DefaultOAuth2AuthenticationScopeResolver(OAuth2TokenRepository tokenRepo) {
    this.tokenRepo = tokenRepo;
  }

  @Override
  public Set<String> resolveScope(OAuth2Authentication auth) {

    OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();

    if (isNull(details) || isNull(details.getTokenValue())) {
      return auth.getOAuth2Request().getScope();
    }

    OAuth2AccessTokenEntity accessTokenEntity =
        tokenRepo.getAccessTokenByValue(details.getTokenValue());

    if (isNull(accessTokenEntity)) {
      throw new IllegalArgumentException("Invalid token");
    } else {
      return accessTokenEntity.getScope();
    }

  }

}
