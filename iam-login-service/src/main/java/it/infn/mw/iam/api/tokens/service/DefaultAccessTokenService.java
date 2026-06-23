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
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;

@Service
public class DefaultAccessTokenService extends AbstractTokenService<AccessToken> {

  private final IamOAuthAccessTokenRepository tokenRepository;

  public DefaultAccessTokenService(Clock clock, TokenRevocationService revokeService,
      IamAccountService accountService, ScimResourceLocationProvider resourceLocationProvider,
      IamOAuthAccessTokenRepository tokenRepository) {

    super(clock, revokeService, accountService, resourceLocationProvider);
    this.tokenRepository = tokenRepository;
  }

  private Page<AccessToken> getAllValidTokens(OffsetPageable op) {

    return tokenRepository.findAllValidAccessTokens(now(), op).map(this::toAccessToken);
  }

  private long countAllValidTokens() {

    return tokenRepository.countValidAccessTokens(now());
  }

  private Page<AccessToken> getAllValidTokensForUser(String userId, OffsetPageable op) {

    return tokenRepository.findValidAccessTokensForUser(userId, now(), op).map(this::toAccessToken);
  }

  private long countAllValidTokensForUser(String userId) {

    return tokenRepository.countValidAccessTokensForUser(userId, now());
  }

  private Page<AccessToken> getAllValidTokensForClient(String clientId, OffsetPageable op) {

    return tokenRepository.findValidAccessTokensForClient(clientId, now(), op)
      .map(this::toAccessToken);
  }

  private long countAllValidTokensForClient(String clientId) {

    return tokenRepository.countValidAccessTokensForClient(clientId, now());
  }

  private Page<AccessToken> getAllValidTokensForUserAndClient(String username, String clientId,
      OffsetPageable op) {

    return tokenRepository.findValidAccessTokensForUserAndClient(username, clientId, now(), op)
      .map(this::toAccessToken);
  }

  private long countAllValidTokensForUserAndClient(String username, String clientId) {

    return tokenRepository.countValidAccessTokensForUserAndClient(username, clientId, now());
  }

  @Override
  public ListResponseDTO<AccessToken> getAllTokens(TokensPageRequest pageRequest) {

    long count = countAllValidTokens();

    if (isCountRequest(pageRequest)) {

      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<AccessToken> entities = getAllValidTokens(op);
    return buildListResponse(entities.getContent(), op, count);
  }

  @Override
  public ListResponseDTO<AccessToken> getTokensForUser(String username,
      TokensPageRequest pageRequest) {

    long count = countAllValidTokensForUser(username);

    if (isCountRequest(pageRequest)) {
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<AccessToken> entities = getAllValidTokensForUser(username, op);
    return buildListResponse(entities.getContent(), op, count);
  }

  @Override
  public ListResponseDTO<AccessToken> getTokensForClient(String clientId,
      TokensPageRequest pageRequest) {

    long count = countAllValidTokensForClient(clientId);

    if (isCountRequest(pageRequest)) {
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<AccessToken> entities = getAllValidTokensForClient(clientId, op);
    return buildListResponse(entities.getContent(), op, count);
  }

  @Override
  public ListResponseDTO<AccessToken> getTokensForClientAndUser(String username, String clientId,
      TokensPageRequest pageRequest) {

    long count = countAllValidTokensForUserAndClient(username, clientId);

    if (isCountRequest(pageRequest)) {
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<AccessToken> entities = getAllValidTokensForUserAndClient(username, clientId, op);
    return buildListResponse(entities.getContent(), op, count);
  }

  @Override
  public void revoke(Long id) {

    tokenRepository.findById(id).ifPresent(this.revocationService::revokeAccessToken);
  }

  @Override
  public Optional<AccessToken> getToken(Long id) {

    return tokenRepository.findById(id).map(this::toAccessToken);
  }

  @Override
  public List<AccessToken> getAllTokensForUser(String username) {

    return tokenRepository.findAccessTokensForUser(username)
      .stream()
      .map(this::toAccessToken)
      .toList();
  }
}
