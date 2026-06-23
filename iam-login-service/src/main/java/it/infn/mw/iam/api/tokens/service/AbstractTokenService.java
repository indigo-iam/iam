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
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.model.SavedUserAuthentication;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.ClientRef;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.api.tokens.model.UserRef;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;

public abstract class AbstractTokenService<T> implements TokenService<T> {

  protected final Clock clock;
  protected final TokenRevocationService revocationService;
  protected final IamAccountService accountService;
  protected final ScimResourceLocationProvider resourceLocationProvider;

  protected AbstractTokenService(Clock clock, TokenRevocationService revocationService,
      IamAccountService accountService, ScimResourceLocationProvider resourceLocationProvider) {

    this.clock = clock;
    this.revocationService = revocationService;
    this.accountService = accountService;
    this.resourceLocationProvider = resourceLocationProvider;
  }

  protected Date now() {

    return Date.from(clock.instant());
  }

  protected OffsetPageable getOffsetPageable(TokensPageRequest pageRequest) {

    if (pageRequest.count() == 0) {
      return new OffsetPageable(0, 1);
    }
    return new OffsetPageable(pageRequest.startIndex() - 1, pageRequest.count());
  }

  protected boolean isCountRequest(TokensPageRequest pageRequest) {

    return pageRequest.count() == 0;
  }

  protected ListResponseDTO<T> buildListResponse(List<T> resources, OffsetPageable op,
      long totalElements) {

    ListResponseDTO.Builder<T> builder = ListResponseDTO.builder();
    builder.itemsPerPage(resources.size());
    builder.startIndex((int) op.getOffset() + 1);
    builder.resources(resources);
    builder.totalResults(totalElements);
    return builder.build();
  }

  protected AccessToken toAccessToken(OAuth2AccessTokenEntity entity) {
    return new AccessToken(entity.getId(), entity.getValue(), entity.getScope(),
        entity.getExpiration(), entity.getClient().getClientId(), toClientRef(entity.getClient()),
        toUserRef(entity.getAuthenticationHolder().getUserAuth()),
        entity.getRefreshToken() != null ? entity.getRefreshToken().getId() : null);
  }

  protected RefreshToken toRefreshToken(OAuth2RefreshTokenEntity entity) {
    return new RefreshToken(entity.getId(), entity.getValue(), entity.getExpiration(),
        entity.getAuthenticationHolder().getScope(), entity.getClient().getClientId(),
        toClientRef(entity.getClient()), toUserRef(entity.getAuthenticationHolder().getUserAuth()));
  }

  protected ClientRef toClientRef(ClientDetailsEntity entity) {
    if (entity == null) {
      return null;
    }

    return new ClientRef(entity.getId(), entity.getClientId(), entity.getClientName(),
        entity.getContacts(), entity.getClientUri());
  }

  protected UserRef toUserRef(SavedUserAuthentication savedUserAuthentication) {
    if (savedUserAuthentication == null) {
      return null;
    }
    IamAccount a = accountService.findByUsername(savedUserAuthentication.getName())
      .orElseThrow(() -> new IllegalStateException("Owner of the token not found"));
    return new UserRef(a.getUuid(), a.getUsername(),
        resourceLocationProvider.userLocation(a.getUuid()));
  }

  protected ListResponseDTO<T> buildCountResponse(long countResponse) {

    return new ListResponseDTO.Builder<T>().totalResults(countResponse)
      .resources(Collections.emptyList())
      .startIndex(1)
      .itemsPerPage(0)
      .build();
  }
}
