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
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@Service
public class DefaultRefreshTokenService extends AbstractTokenService<RefreshToken> {

  private final IamOAuthRefreshTokenRepository tokenRepository;

  public DefaultRefreshTokenService(Clock clock, TokenRevocationService revokeService,
      IamAccountService accountService, ScimResourceLocationProvider resourceLocationProvider,
      IamOAuthRefreshTokenRepository tokenRepository) {

    super(clock, revokeService, accountService, resourceLocationProvider);
    this.tokenRepository = tokenRepository;
  }

  private Page<RefreshToken> getAllValidTokens(OffsetPageable op) {

    return tokenRepository.findAllValidRefreshTokens(now(), op).map(this::toRefreshToken);
  }

  private long countAllValidTokens() {

    return tokenRepository.countValidRefreshTokens(now());
  }

  private Page<RefreshToken> getAllValidTokensForUser(String userId, OffsetPageable op) {

    return tokenRepository.findValidRefreshTokensForUser(userId, now(), op)
      .map(this::toRefreshToken);
  }

  private long countAllValidTokensForUser(String userId) {

    return tokenRepository.countValidRefreshTokensForUser(userId, now());
  }

  private Page<RefreshToken> getAllValidTokensForClient(String clientId, OffsetPageable op) {

    return tokenRepository.findValidRefreshTokensForClient(clientId, now(), op)
      .map(this::toRefreshToken);
  }

  private long countAllValidTokensForClient(String clientId) {

    return tokenRepository.countValidRefreshTokensForClient(clientId, now());
  }

  private Page<RefreshToken> getAllValidTokensForUserAndClient(String username, String clientId,
      OffsetPageable op) {

    return tokenRepository.findValidRefreshTokensForUserAndClient(username, clientId, now(), op)
      .map(this::toRefreshToken);
  }

  private long countAllValidTokensForUserAndClient(String username, String clientId) {

    return tokenRepository.countValidRefreshTokensForUserAndClient(username, clientId, now());
  }

  protected RefreshToken toRefreshToken(OAuth2RefreshTokenEntity entity) {
    return new RefreshToken(entity.getId(), entity.getValue(), entity.getExpiration(),
        entity.getAuthenticationHolder().getScope(), entity.getClient().getClientId(),
        toClientRef(entity.getClient()), toUserRef(entity.getAuthenticationHolder().getUserAuth()));
  }

  @Override
  public ListResponseDTO<RefreshToken> getAllTokens(TokensPageRequest pageRequest) {

    long count = countAllValidTokens();

    if (isCountRequest(pageRequest)) {
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<RefreshToken> entities = getAllValidTokens(op);
    return buildListResponse(entities.getContent(), op, count);
  }


  @Override
  public ListResponseDTO<RefreshToken> getTokensForUser(String username,
      TokensPageRequest pageRequest) {

    long count = countAllValidTokensForUser(username);

    if (isCountRequest(pageRequest)) {
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<RefreshToken> entities = getAllValidTokensForUser(username, op);
    return buildListResponse(entities.getContent(), op, count);
  }

  @Override
  public ListResponseDTO<RefreshToken> getTokensForClient(String clientId,
      TokensPageRequest pageRequest) {

    long count = countAllValidTokensForClient(clientId);

    if (isCountRequest(pageRequest)) {
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<RefreshToken> entities = getAllValidTokensForClient(clientId, op);
    return buildListResponse(entities.getContent(), op, count);
  }

  @Override
  public ListResponseDTO<RefreshToken> getTokensForClientAndUser(String username, String clientId,
      TokensPageRequest pageRequest) {

    long count = countAllValidTokensForUserAndClient(username, clientId);

    if (isCountRequest(pageRequest)) {
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<RefreshToken> entities = getAllValidTokensForUserAndClient(username, clientId, op);
    return buildListResponse(entities.getContent(), op, count);
  }

  @Override
  public void revoke(Long id) {

    tokenRepository.findById(id).ifPresent(revocationService::revokeRefreshToken);
  }

  @Override
  public Optional<RefreshToken> getToken(Long id) {

    return tokenRepository.findById(id).map(this::toRefreshToken);
  }

  @Override
  public List<RefreshToken> getAllTokensForUser(String username) {

    return tokenRepository.findRefreshTokensForUser(username)
      .stream()
      .map(this::toRefreshToken)
      .toList();
  }
}
