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
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.tokens.converter.TokensConverter;
import it.infn.mw.iam.api.tokens.exception.TokenNotFoundException;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;

@Service
public class DefaultAccessTokenService extends AbstractTokenService<AccessToken> {

  @Autowired
  private TokensConverter tokensConverter;

  @Autowired
  private DefaultOAuth2ProviderTokenService tokenService;

  @Autowired
  private IamOAuthAccessTokenRepository tokenRepository;

  @Override
  public AccessToken getTokenById(Long id) {

    OAuth2AccessTokenEntity at =
        getAccessTokenById(id).orElseThrow(() -> new TokenNotFoundException(id));
    return tokensConverter.toAccessToken(at);
  }

  @Override
  public void revokeTokenById(Long id) {

    OAuth2AccessTokenEntity at =
        getAccessTokenById(id).orElseThrow(() -> new TokenNotFoundException(id));
    tokenService.revokeAccessToken(at);
  }

  private Optional<OAuth2AccessTokenEntity> getAccessTokenById(Long accessTokenId) {

    OAuth2AccessTokenEntity at = tokenService.getAccessTokenById(accessTokenId);
    return Optional.ofNullable(at);
  }

  private Page<OAuth2AccessTokenEntity> getAllValidTokens(OffsetPageable op) {

    return tokenRepository.findAllValidAccessTokens(new Date(), op);
  }

  private long countAllValidTokens() {

    return tokenRepository.countValidAccessTokens(new Date());
  }

  private Page<OAuth2AccessTokenEntity> getAllValidTokensForUser(String userId, OffsetPageable op) {

    return tokenRepository.findValidAccessTokensForUser(userId, new Date(), op);
  }

  private long countAllValidTokensForUser(String userId) {

    return tokenRepository.countValidAccessTokensForUser(userId, new Date());
  }

  private Page<OAuth2AccessTokenEntity> getAllValidTokensForClient(String clientId,
      OffsetPageable op) {

    return tokenRepository.findValidAccessTokensForClient(clientId, new Date(), op);
  }

  private long countAllValidTokensForClient(String clientId) {

    return tokenRepository.countValidAccessTokensForClient(clientId, new Date());
  }

  private Page<OAuth2AccessTokenEntity> getAllValidTokensForUserAndClient(String userId,
      String clientId, OffsetPageable op) {

    return tokenRepository.findValidAccessTokensForUserAndClient(userId, clientId, new Date(), op);
  }

  private long countAllValidTokensForUserAndClient(String userId, String clientId) {

    return tokenRepository.countValidAccessTokensForUserAndClient(userId, clientId, new Date());
  }

  private ListResponseDTO<AccessToken> buildCountResponse(long countResponse) {

    return new ListResponseDTO.Builder<AccessToken>().totalResults(countResponse)
        .resources(Collections.emptyList()).startIndex(1).itemsPerPage(0).build();
  }

  private ListResponseDTO<AccessToken> buildListResponse(Page<OAuth2AccessTokenEntity> entities, OffsetPageable op) {

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

  @Override
  public void deleteAllTokens() {

    tokenRepository.deleteAll();
  }
}
