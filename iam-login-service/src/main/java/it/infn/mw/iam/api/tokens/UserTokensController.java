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

import org.mitre.oauth2.view.TokenApiView;
import org.mitre.openid.connect.view.HttpCodeView;
import org.mitre.openid.connect.view.JsonEntityView;
import org.mitre.openid.connect.view.JsonErrorView;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.api.tokens.service.TokenService;
import it.infn.mw.iam.persistence.model.IamAccount;

@Controller
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
  public String getUserAccessTokens(Authentication auth, ModelMap m) {

    IamAccount authenticatedUser = getAuthenticatedUserOrFail(auth);
    List<AccessToken> tokens =
        accessTokenService.getAllTokensForUser(authenticatedUser.getUsername());
    m.put(JsonEntityView.ENTITY, tokens);
    return TokenApiView.VIEWNAME;
  }

  @PreAuthorize("hasRole('USER')")
  @GetMapping(value = {"/api/tokens/refresh", "/iam/api/tokens/refresh"})
  public String getUserRefreshTokens(Authentication auth, ModelMap m) {

    IamAccount authenticatedUser = getAuthenticatedUserOrFail(auth);
    List<RefreshToken> tokens =
        refreshTokenService.getAllTokensForUser(authenticatedUser.getUsername());
    m.put(JsonEntityView.ENTITY, tokens);
    return TokenApiView.VIEWNAME;
  }

  @PreAuthorize("hasRole('USER')")
  @DeleteMapping(value = {"/api/tokens/access/{id}", "/iam/api/tokens/access/{id}"})
  public String deleteAccessToken(@PathVariable Long id, Authentication auth, ModelMap m) {

    IamAccount authenticatedUser = getAuthenticatedUserOrFail(auth);
    Optional<AccessToken> token = accessTokenService.getToken(id);
    if (token.isEmpty()) {
      m.put(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
      m.put(JsonErrorView.ERROR_MESSAGE,
          "The requested token with id " + id + " could not be found.");
      return JsonErrorView.VIEWNAME;
    }
    if (!token.get().user().username().equals(authenticatedUser.getUsername())) {
      m.put(HttpCodeView.CODE, HttpStatus.FORBIDDEN);
      m.put(JsonErrorView.ERROR_MESSAGE, "You do not have permission to view this token");
      return JsonErrorView.VIEWNAME;
    }
    accessTokenService.revoke(id);
    return HttpCodeView.VIEWNAME;
  }

  @PreAuthorize("hasRole('USER')")
  @DeleteMapping(value = {"/api/tokens/refresh/{id}", "/iam/api/tokens/access/{id}"})
  public String deleteRefreshToken(@PathVariable Long id, Authentication auth, ModelMap m) {

    IamAccount authenticatedUser = getAuthenticatedUserOrFail(auth);
    Optional<RefreshToken> token = refreshTokenService.getToken(id);
    if (token.isEmpty()) {
      m.put(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
      m.put(JsonErrorView.ERROR_MESSAGE,
          "The requested token with id " + id + " could not be found.");
      return JsonErrorView.VIEWNAME;
    }
    if (!token.get().user().username().equals(authenticatedUser.getUsername())) {
      m.put(HttpCodeView.CODE, HttpStatus.FORBIDDEN);
      m.put(JsonErrorView.ERROR_MESSAGE, "You do not have permission to view this token");
      return JsonErrorView.VIEWNAME;
    }
    refreshTokenService.revoke(id);
    return HttpCodeView.VIEWNAME;
  }

  private IamAccount getAuthenticatedUserOrFail(Authentication auth) {
    return accountUtils.getAuthenticatedUserAccount(auth)
        .orElseThrow(() -> new IllegalStateException("Invalid authenticated account"));
  }
}
