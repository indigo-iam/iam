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

import java.time.LocalDate;
import java.util.Date;
import java.util.Set;

import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientLastUsedEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;

import it.infn.mw.iam.audit.events.tokens.AccessTokenIssuedEvent;
import it.infn.mw.iam.audit.events.tokens.RefreshTokenIssuedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@Service("defaultOAuth2ProviderTokenService")
@Primary
public class IamTokenService extends DefaultOAuth2ProviderTokenService {

  public static final Logger LOG = LoggerFactory.getLogger(IamTokenService.class);

  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final ApplicationEventPublisher eventPublisher;
  private final IamProperties iamProperties;


  public IamTokenService(IamOAuthAccessTokenRepository atRepo,
      IamOAuthRefreshTokenRepository rtRepo, ApplicationEventPublisher publisher,
      IamProperties iamProperties) {

    this.accessTokenRepo = atRepo;
    this.refreshTokenRepo = rtRepo;
    this.eventPublisher = publisher;
    this.iamProperties = iamProperties;
  }

  @Override
  public Set<OAuth2AccessTokenEntity> getAllAccessTokensForUser(String id) {

    Set<OAuth2AccessTokenEntity> results = Sets.newLinkedHashSet();
    results.addAll(accessTokenRepo.findValidAccessTokensForUser(id, new Date()));
    return results;
  }


  @Override
  public Set<OAuth2RefreshTokenEntity> getAllRefreshTokensForUser(String id) {
    Set<OAuth2RefreshTokenEntity> results = Sets.newLinkedHashSet();
    results.addAll(refreshTokenRepo.findValidRefreshTokensForUser(id, new Date()));
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
  @SuppressWarnings("deprecation")
  public OAuth2AccessTokenEntity createAccessToken(OAuth2Authentication authentication) {

    OAuth2AccessTokenEntity token = super.createAccessToken(authentication);

    if (iamProperties.getClient().isTrackLastUsed()) {
      updateClientLastUsed(token);
    }

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, token));
    return token;
  }

  @Override
  public OAuth2RefreshTokenEntity createRefreshToken(ClientDetailsEntity client,
      AuthenticationHolderEntity authHolder) {

    OAuth2RefreshTokenEntity token = super.createRefreshToken(client, authHolder);

    eventPublisher.publishEvent(new RefreshTokenIssuedEvent(this, token));
    return token;
  }

  @Override
  @SuppressWarnings("deprecation")
  public OAuth2AccessTokenEntity refreshAccessToken(String refreshTokenValue,
      TokenRequest authRequest) {

    OAuth2AccessTokenEntity token = super.refreshAccessToken(refreshTokenValue, authRequest);

    if (iamProperties.getClient().isTrackLastUsed()) {
      updateClientLastUsed(token);
    }

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, token));
    return token;
  }

  private void updateClientLastUsed(OAuth2AccessTokenEntity token) {
    ClientDetailsEntity client = token.getClient();
    ClientLastUsedEntity clientLastUsed = client.getClientLastUsed();
    LocalDate now = LocalDate.now();

    if (clientLastUsed == null) {
      clientLastUsed = new ClientLastUsedEntity(client, now);
      client.setClientLastUsed(clientLastUsed);
    } else {
      LocalDate lastUsed = clientLastUsed.getLastUsed();
      if (lastUsed.isBefore(now)) {
        clientLastUsed.setLastUsed(now);
      }
    }
  }
}
