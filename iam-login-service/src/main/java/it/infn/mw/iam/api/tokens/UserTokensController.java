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
package it.infn.mw.iam.api.tokens;

import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedUserException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.tokens.exception.TokenNotFoundException;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.api.tokens.service.TokenService;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
@RestController
public class UserTokensController {

  private final AccountUtils accountUtils;
  private final TokenService<AccessToken> accessTokenService;
  private final TokenService<RefreshToken> refreshTokenService;

  public UserTokensController(AccountUtils accountUtils,
      TokenService<AccessToken> accessTokenService,
      TokenService<RefreshToken> refreshTokenService) {
    this.accountUtils = accountUtils;
    this.accessTokenService = accessTokenService;
    this.refreshTokenService = refreshTokenService;
  }

  @PreAuthorize("hasRole('USER')")
  @GetMapping(value = {"/api/tokens/access", "/iam/api/tokens/access"})
  public List<AccessToken> getUserAccessTokens(Authentication auth) {

    IamAccount authenticatedUser = getAuthenticatedUserOrFail(auth);
    return accessTokenService.getAllTokensForUser(authenticatedUser.getUsername());
  }

  @PreAuthorize("hasRole('USER')")
  @GetMapping(value = {"/api/tokens/refresh", "/iam/api/tokens/refresh"})
  public List<RefreshToken> getUserRefreshTokens(Authentication auth) {

    IamAccount authenticatedUser = getAuthenticatedUserOrFail(auth);
    return refreshTokenService.getAllTokensForUser(authenticatedUser.getUsername());
  }

  @PreAuthorize("hasRole('USER')")
  @DeleteMapping(value = {"/api/tokens/access/{id}", "/iam/api/tokens/access/{id}"})
  public void deleteAccessToken(@PathVariable Long id, Authentication auth) {

    IamAccount authenticatedUser = getAuthenticatedUserOrFail(auth);
    Optional<AccessToken> token = accessTokenService.getToken(id);
    if (token.isEmpty()) {
      throw new TokenNotFoundException("The requested token with id " + id + " could not be found.");
    }
    if (!token.get().user().username().equals(authenticatedUser.getUsername())) {
      throw new UnauthorizedUserException("You do not have permission to view this token");
    }
    accessTokenService.revoke(id);
  }

  @PreAuthorize("hasRole('USER')")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @DeleteMapping(value = {"/api/tokens/refresh/{id}", "/iam/api/tokens/refresh/{id}"})
  public void deleteRefreshToken(@PathVariable Long id, Authentication auth) {

    IamAccount authenticatedUser = getAuthenticatedUserOrFail(auth);
    Optional<RefreshToken> token = refreshTokenService.getToken(id);
    if (token.isEmpty()) {
      throw new TokenNotFoundException("The requested token with id " + id + " could not be found.");
    }
    if (!token.get().user().username().equals(authenticatedUser.getUsername())) {
      throw new UnauthorizedUserException("You do not have permission to view this token");
    }
    refreshTokenService.revoke(id);
  }

  private IamAccount getAuthenticatedUserOrFail(Authentication auth) {
    return accountUtils.getAuthenticatedUserAccount(auth)
      .orElseThrow(() -> new IllegalStateException("Invalid authenticated account"));
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(TokenNotFoundException.class)
  public ErrorDTO tokenNotFoundError(Exception ex) {

    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.FORBIDDEN)
  @ExceptionHandler(UnauthorizedUserException.class)
  public ErrorDTO unauthorizedUserError(Exception ex) {

    return ErrorDTO.fromString(ex.getMessage());
  }
}
