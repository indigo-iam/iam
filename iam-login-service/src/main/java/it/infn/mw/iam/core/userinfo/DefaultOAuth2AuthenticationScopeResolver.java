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

import static it.infn.mw.iam.core.IamTokenService.sha256;
import static java.util.Objects.isNull;

import java.util.Optional;
import java.util.Set;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;

@Component
@SuppressWarnings("deprecation")
public class DefaultOAuth2AuthenticationScopeResolver implements OAuth2AuthenticationScopeResolver {

  private final IamOAuthAccessTokenRepository accessTokenRepository;

  public DefaultOAuth2AuthenticationScopeResolver(
      IamOAuthAccessTokenRepository accessTokenRepository) {
    this.accessTokenRepository = accessTokenRepository;
  }

  @Override
  public Set<String> resolveScope(OAuth2Authentication auth) {

    OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();

    if (isNull(details) || isNull(details.getTokenValue())) {
      return auth.getOAuth2Request().getScope();
    }

    Optional<OAuth2AccessTokenEntity> accessTokenEntity =
        accessTokenRepository.findByTokenValue(sha256(details.getTokenValue()));

    if (accessTokenEntity.isPresent()) {
      return accessTokenEntity.get().getScope();
    }
    throw new IllegalArgumentException("Invalid token");
  }

}
