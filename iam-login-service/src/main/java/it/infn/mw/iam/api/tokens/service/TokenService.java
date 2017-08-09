package it.infn.mw.iam.api.tokens.service;

import it.infn.mw.iam.api.tokens.exception.TokenNotFoundException;
import it.infn.mw.iam.api.tokens.model.TokensListResponse;
import it.infn.mw.iam.api.tokens.service.filtering.TokensFilterRequest;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;

public interface TokenService<T> {

  TokensListResponse<T> getList(final TokensPageRequest pageRequest, final TokensFilterRequest filterRequest);

  T getToken(Long id) throws TokenNotFoundException;

  void revokeToken(Long id) throws TokenNotFoundException;

}
