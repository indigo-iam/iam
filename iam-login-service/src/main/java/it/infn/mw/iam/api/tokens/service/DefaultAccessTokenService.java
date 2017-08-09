package it.infn.mw.iam.api.tokens.service;

import it.infn.mw.iam.api.tokens.converter.TokensConverter;
import it.infn.mw.iam.api.tokens.exception.TokenNotFoundException;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.TokensListResponse;
import it.infn.mw.iam.api.tokens.service.filtering.TokensFilterRequest;
import it.infn.mw.iam.api.tokens.service.paging.OffsetPageable;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class DefaultAccessTokenService implements TokenService<AccessToken> {

  @Autowired
  private TokensConverter accessTokenConverter;

  @Autowired
  private DefaultOAuth2ProviderTokenService tokenService;

  @Autowired
  private IamOAuthAccessTokenRepository tokenRepository;

  @Override
  public AccessToken getToken(Long id) throws TokenNotFoundException {

    OAuth2AccessTokenEntity at = getAccessTokenById(id).orElseThrow(TokenNotFoundException::new);
    return accessTokenConverter.toAccessToken(at);
  }

  @Override
  public void revokeToken(Long id) throws TokenNotFoundException {

    OAuth2AccessTokenEntity at = getAccessTokenById(id).orElseThrow(TokenNotFoundException::new);
    tokenService.revokeAccessToken(at);
  }

  private Optional<OAuth2AccessTokenEntity> getAccessTokenById(Long accessTokenId) {

    OAuth2AccessTokenEntity at = tokenService.getAccessTokenById(accessTokenId);
    return at != null ? Optional.of(at) : Optional.empty();
  }

  private Page<OAuth2AccessTokenEntity> getFilteredList(TokensFilterRequest filters,
      OffsetPageable op) {

    Date now = new Date();
    Optional<String> userId = filters.getUserId();
    Optional<String> clientId = filters.getClientId();

    if (userId.isPresent() && clientId.isPresent()) {

      return tokenRepository.findValidAccessTokensForUserAndClient(userId.get(), clientId.get(),
          now, op);
    }

    if (userId.isPresent()) {

      return tokenRepository.findValidAccessTokensForUser(userId.get(), now, op);
    }

    if (clientId.isPresent()) {

      return tokenRepository.findValidAccessTokensForClient(clientId.get(), now, op);
    }

    return tokenRepository.findAllValidAccessTokens(now, op);
  }

  @Override
  public TokensListResponse<AccessToken> getList(TokensPageRequest params,
      TokensFilterRequest filters) {

    if (params.getCount() == 0) {
      int tokenCount = tokenRepository.countAllTokens();
      return new TokensListResponse<>(Collections.emptyList(), tokenCount, 0, 1);
    }

    OffsetPageable op = new OffsetPageable(params.getStartIndex(), params.getCount());
    Page<OAuth2AccessTokenEntity> results = null;

    results = getFilteredList(filters, op);

    List<AccessToken> resources = new ArrayList<>();

    results.getContent().forEach(a -> {
      if (!a.isExpired()) {
        resources.add(accessTokenConverter.toAccessToken(a));
      }
    });

    return new TokensListResponse<>(resources, results.getTotalElements(), resources.size(),
        op.getOffset() + 1);
  }
}
