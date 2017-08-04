package it.infn.mw.iam.api.tokens.service;

import it.infn.mw.iam.api.tokens.converter.TokensConverter;
import it.infn.mw.iam.api.tokens.exception.TokenNotFoundException;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.api.tokens.model.TokensListResponse;
import it.infn.mw.iam.api.tokens.service.filtering.TokensFilterRequest;
import it.infn.mw.iam.api.tokens.service.paging.OffsetPageable;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
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
public class DefaultRefreshTokenService implements TokenService<RefreshToken> {

  @Autowired
  private TokensConverter tokensConverter;

  @Autowired
  private DefaultOAuth2ProviderTokenService tokenService;

  @Autowired
  private IamOAuthRefreshTokenRepository tokenRepository;

  @Override
  public RefreshToken getToken(Long id) throws TokenNotFoundException {

    OAuth2RefreshTokenEntity rt = getRefreshTokenById(id).orElseThrow(TokenNotFoundException::new);
    return tokensConverter.toRefreshToken(rt);
  }

  @Override
  public void revokeToken(Long id) throws TokenNotFoundException {

    OAuth2RefreshTokenEntity rt = getRefreshTokenById(id).orElseThrow(TokenNotFoundException::new);
    tokenService.revokeRefreshToken(rt);
  }

  private Optional<OAuth2RefreshTokenEntity> getRefreshTokenById(Long refreshTokenId) {

    OAuth2RefreshTokenEntity at = tokenService.getRefreshTokenById(refreshTokenId);
    return at != null ? Optional.of(at) : Optional.empty();
  }


  private Page<OAuth2RefreshTokenEntity> getFilteredList(TokensFilterRequest filters,
      OffsetPageable op) {

    Date now = new Date();
    String userId = emptyIfNull(filters.getUserId());
    String clientId = emptyIfNull(filters.getClientId());

    return tokenRepository.findValidTokensForUserAndClientLike(userId, clientId, now, op);
  }

  @Override
  public TokensListResponse<RefreshToken> getList(TokensPageRequest params,
      TokensFilterRequest filters) {

    if (params.getCount() == 0) {
      int tokenCount = tokenRepository.countAllTokens();
      return new TokensListResponse<>(Collections.emptyList(), tokenCount, 0, 1);
    }

    OffsetPageable op = new OffsetPageable(params.getStartIndex(), params.getCount());
    Page<OAuth2RefreshTokenEntity> results = null;

    results = getFilteredList(filters, op);

    List<RefreshToken> resources = new ArrayList<>();

    results.getContent().forEach(r -> {
      if (!r.isExpired()) {
        resources.add(tokensConverter.toRefreshToken(r));
      }
    });

    return new TokensListResponse<>(resources, results.getTotalElements(), resources.size(),
        op.getOffset() + 1);
  }

  private String emptyIfNull(String s) {
    return s != null ? s : "";
  }
}
