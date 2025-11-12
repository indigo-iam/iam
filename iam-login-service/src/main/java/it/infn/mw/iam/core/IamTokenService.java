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
package it.infn.mw.iam.core;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;
import com.google.common.hash.Hashing;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.audit.events.tokens.AccessTokenIssuedEvent;
import it.infn.mw.iam.audit.events.tokens.RefreshTokenIssuedEvent;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@SuppressWarnings("deprecation")
@Service("defaultOAuth2ProviderTokenService")
@Primary
public class IamTokenService extends DefaultOAuth2ProviderTokenService {

  public static final Logger LOG = LoggerFactory.getLogger(IamTokenService.class);

  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final ClientService clientService;
  private final ApplicationEventPublisher eventPublisher;
  private final IamProperties iamProperties;
  private final ScopeFilter scopeFilter;

  public IamTokenService(IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo, ClientService clientService, ApplicationEventPublisher eventPublisher,
      IamProperties iamProperties, ScopeFilter scopeFilter) {

    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.clientService = clientService;
    this.eventPublisher = eventPublisher;
    this.iamProperties = iamProperties;
    this.scopeFilter = scopeFilter;
  }

  @Override
  public Set<OAuth2AccessTokenEntity> getAllAccessTokensForUser(String id) {

    Set<OAuth2AccessTokenEntity> results = Sets.newLinkedHashSet();
    results.addAll(accessTokenRepo.findAccessTokensForUser(id));
    return results;
  }


  @Override
  public Set<OAuth2RefreshTokenEntity> getAllRefreshTokensForUser(String id) {
    Set<OAuth2RefreshTokenEntity> results = Sets.newLinkedHashSet();
    results.addAll(refreshTokenRepo.findRefreshTokensForUser(id));
    return results;
  }

  @Override
  public void revokeAccessToken(OAuth2AccessTokenEntity accessToken) {
    accessTokenRepo.delete(accessToken);
  }

  @Override
  public void revokeRefreshToken(OAuth2RefreshTokenEntity refreshToken) {
    refreshTokenRepo.delete(refreshToken);
  }

  @Override
  public OAuth2AccessTokenEntity createAccessToken(OAuth2Authentication authentication) {

    if (authentication.getUserAuthentication() != null && 
      authentication.getUserAuthentication().getAuthorities() != null &&
      authentication.getUserAuthentication()
      .getAuthorities()
      .contains(Authorities.ROLE_PRE_AUTHENTICATED)) {
      throw new InvalidGrantException("User is not fully authenticated.");
    } 
    OAuth2AccessTokenEntity token = super.createAccessToken(scopeFilter.filterScopes(authentication));

    if (iamProperties.getClient().isTrackLastUsed()) {
      clientService.useClient(token.getClient());
    }

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, token));
    return token;
  }

  @Override
  public OAuth2RefreshTokenEntity createRefreshToken(ClientDetailsEntity client,
      AuthenticationHolderEntity authHolder) {

    OAuth2RefreshTokenEntity token = super.createRefreshToken(client, scopeFilter.filterScopes(authHolder));

    eventPublisher.publishEvent(new RefreshTokenIssuedEvent(this, token));
    return token;
  }

  @Override
  public OAuth2AccessTokenEntity refreshAccessToken(String refreshTokenValue,
      TokenRequest authRequest) {

    OAuth2AccessTokenEntity token = super.refreshAccessToken(refreshTokenValue, authRequest);

    if (iamProperties.getClient().isTrackLastUsed()) {
      clientService.useClient(token.getClient());
    }

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, token));
    return token;
  }

  public static String sha256(String tokenString) {
    return Hashing.sha256().hashString(tokenString, StandardCharsets.UTF_8).toString();
  }
}
