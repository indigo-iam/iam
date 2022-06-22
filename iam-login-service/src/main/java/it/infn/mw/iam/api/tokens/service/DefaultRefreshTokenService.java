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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.tokens.converter.TokensConverter;
import it.infn.mw.iam.api.tokens.exception.TokenNotFoundException;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@Service
public class DefaultRefreshTokenService extends AbstractTokenService<RefreshToken> {

  @Autowired
  private TokensConverter tokensConverter;

  @Autowired
  private DefaultOAuth2ProviderTokenService tokenService;

  @Autowired
  private IamOAuthRefreshTokenRepository tokenRepository;

  @Override
  public RefreshToken getTokenById(Long id) {

    OAuth2RefreshTokenEntity rt =
        getRefreshTokenById(id).orElseThrow(() -> new TokenNotFoundException(id));
    return tokensConverter.toRefreshToken(rt);
  }

  @Override
  public void revokeTokenById(Long id) {

    OAuth2RefreshTokenEntity rt =
        getRefreshTokenById(id).orElseThrow(() -> new TokenNotFoundException(id));
    tokenService.revokeRefreshToken(rt);
  }

  private Optional<OAuth2RefreshTokenEntity> getRefreshTokenById(Long refreshTokenId) {

    OAuth2RefreshTokenEntity at = tokenService.getRefreshTokenById(refreshTokenId);
    return Optional.ofNullable(at);
  }

  private Page<OAuth2RefreshTokenEntity> getAllValidTokens(OffsetPageable op) {

    return tokenRepository.findAllValidRefreshTokens(new Date(), op);
  }

  private long countAllValidTokens() {

    return tokenRepository.countValidRefreshTokens(new Date());
  }

  private Page<OAuth2RefreshTokenEntity> getAllValidTokensForUser(String userId,
      OffsetPageable op) {

    return tokenRepository.findValidRefreshTokensForUser(userId, new Date(), op);
  }

  private long countAllValidTokensForUser(String userId) {

    return tokenRepository.countValidRefreshTokensForUser(userId, new Date());
  }

  private Page<OAuth2RefreshTokenEntity> getAllValidTokensForClient(String clientId,
      OffsetPageable op) {

    return tokenRepository.findValidRefreshTokensForClient(clientId, new Date(), op);
  }

  private long countAllValidTokensForClient(String clientId) {

    return tokenRepository.countValidRefreshTokensForClient(clientId, new Date());
  }

  private Page<OAuth2RefreshTokenEntity> getAllValidTokensForUserAndClient(String userId,
      String clientId, OffsetPageable op) {

    return tokenRepository.findValidRefreshTokensForUserAndClient(userId, clientId, new Date(), op);
  }

  private long countAllValidTokensForUserAndClient(String userId, String clientId) {

    return tokenRepository.countValidRefreshTokensForUserAndClient(userId, clientId, new Date());
  }

  private ListResponseDTO<RefreshToken> buildCountResponse(long countResponse) {

    return new ListResponseDTO.Builder<RefreshToken>().totalResults(countResponse)
        .resources(Collections.emptyList()).startIndex(1).itemsPerPage(0).build();
  }

  private ListResponseDTO<RefreshToken> buildListResponse(Page<OAuth2RefreshTokenEntity> entities,
      OffsetPageable op) {

    List<RefreshToken> resources = new ArrayList<>();
    entities.getContent().forEach(a -> resources.add(tokensConverter.toRefreshToken(a)));
    return buildListResponse(resources, op, entities.getTotalElements());
  }

  @Override
  public ListResponseDTO<RefreshToken> getAllTokens(TokensPageRequest pageRequest) {

    if (isCountRequest(pageRequest)) {

      long count = countAllValidTokens();
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<OAuth2RefreshTokenEntity> entities = getAllValidTokens(op);
    return buildListResponse(entities, op);
  }

  @Override
  public ListResponseDTO<RefreshToken> getTokensForUser(String userId,
      TokensPageRequest pageRequest) {

    if (isCountRequest(pageRequest)) {

      long count = countAllValidTokensForUser(userId);
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<OAuth2RefreshTokenEntity> entities = getAllValidTokensForUser(userId, op);
    return buildListResponse(entities, op);
  }

  @Override
  public ListResponseDTO<RefreshToken> getTokensForClient(String clientId,
      TokensPageRequest pageRequest) {

    if (isCountRequest(pageRequest)) {

      long count = countAllValidTokensForClient(clientId);
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<OAuth2RefreshTokenEntity> entities = getAllValidTokensForClient(clientId, op);
    return buildListResponse(entities, op);
  }

  @Override
  public ListResponseDTO<RefreshToken> getTokensForClientAndUser(String userId, String clientId,
      TokensPageRequest pageRequest) {

    if (isCountRequest(pageRequest)) {

      long count = countAllValidTokensForUserAndClient(userId, clientId);
      return buildCountResponse(count);
    }

    OffsetPageable op = getOffsetPageable(pageRequest);
    Page<OAuth2RefreshTokenEntity> entities =
        getAllValidTokensForUserAndClient(userId, clientId, op);
    return buildListResponse(entities, op);
  }

  @Override
  public void deleteAllTokens() {

    tokenRepository.deleteAll();
  }
}
