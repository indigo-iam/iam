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
package it.infn.mw.iam.api.tokens.service;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.tokens.converter.TokensConverter;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;

@Service
public class DefaultAccessTokenService extends AbstractTokenService<AccessToken> {

  private TokensConverter tokensConverter;
  private IamOAuthAccessTokenRepository tokenRepository;

  public DefaultAccessTokenService(Clock clock, IamProperties properties, TokenRevocationService revokeService,
      IamOAuthAccessTokenRepository tokenRepository,
      TokensConverter tokensConverter) {

    super(clock, properties, revokeService);
    this.tokenRepository = tokenRepository;
    this.tokensConverter = tokensConverter;
  }

  @Override
  public void revokeTokenById(Long id) {

    if (properties.getAccessToken().isStoreOnDatabase()) {
      tokenRepository.findById(id).ifPresent(revokeService::revokeAccessToken);
    } else {
      throw new IllegalStateException("Access Tokens are not stored on database and cannot be retrieved via this API");
    }
  }

  private Page<OAuth2AccessTokenEntity> getAllValidTokens(OffsetPageable op) {

    return tokenRepository.findAllValidAccessTokens(now(), op);
  }

  private long countAllValidTokens() {

    return tokenRepository.countValidAccessTokens(now());
  }

  private Page<OAuth2AccessTokenEntity> getAllValidTokensForUser(String userId, OffsetPageable op) {

    return tokenRepository.findValidAccessTokensForUser(userId, now(), op);
  }

  private long countAllValidTokensForUser(String userId) {

    return tokenRepository.countValidAccessTokensForUser(userId, now());
  }

  private Page<OAuth2AccessTokenEntity> getAllValidTokensForClient(String clientId,
      OffsetPageable op) {

    return tokenRepository.findValidAccessTokensForClient(clientId, now(), op);
  }

  private long countAllValidTokensForClient(String clientId) {

    return tokenRepository.countValidAccessTokensForClient(clientId, now());
  }

  private Page<OAuth2AccessTokenEntity> getAllValidTokensForUserAndClient(String userId,
      String clientId, OffsetPageable op) {

    return tokenRepository.findValidAccessTokensForUserAndClient(userId, clientId, now(), op);
  }

  private long countAllValidTokensForUserAndClient(String userId, String clientId) {

    return tokenRepository.countValidAccessTokensForUserAndClient(userId, clientId, now());
  }

  private ListResponseDTO<AccessToken> buildCountResponse(long countResponse) {

    return new ListResponseDTO.Builder<AccessToken>().totalResults(countResponse)
      .resources(Collections.emptyList())
      .startIndex(1)
      .itemsPerPage(0)
      .build();
  }

  private ListResponseDTO<AccessToken> buildListResponse(Page<OAuth2AccessTokenEntity> entities,
      OffsetPageable op) {

    List<AccessToken> resources = new ArrayList<>();
    entities.getContent().forEach(a -> resources.add(tokensConverter.toAccessToken(a)));
    return buildListResponse(resources, op, entities.getTotalElements());
  }

  @Override
  public ListResponseDTO<AccessToken> getAllTokens(TokensPageRequest pageRequest) {

    if (isCountRequest(pageRequest)) {

      long count = countAllValidTokens();
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<OAuth2AccessTokenEntity> entities = getAllValidTokens(op);
    return buildListResponse(entities, op);
  }

  @Override
  public ListResponseDTO<AccessToken> getTokensForUser(String userId,
      TokensPageRequest pageRequest) {

    if (isCountRequest(pageRequest)) {

      long count = countAllValidTokensForUser(userId);
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<OAuth2AccessTokenEntity> entities = getAllValidTokensForUser(userId, op);
    return buildListResponse(entities, op);
  }

  @Override
  public ListResponseDTO<AccessToken> getTokensForClient(String clientId,
      TokensPageRequest pageRequest) {

    if (isCountRequest(pageRequest)) {

      long count = countAllValidTokensForClient(clientId);
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<OAuth2AccessTokenEntity> entities = getAllValidTokensForClient(clientId, op);
    return buildListResponse(entities, op);
  }

  @Override
  public ListResponseDTO<AccessToken> getTokensForClientAndUser(String userId, String clientId,
      TokensPageRequest pageRequest) {

    if (isCountRequest(pageRequest)) {

      long count = countAllValidTokensForUserAndClient(userId, clientId);
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<OAuth2AccessTokenEntity> entities =
        getAllValidTokensForUserAndClient(userId, clientId, op);
    return buildListResponse(entities, op);
  }
}
