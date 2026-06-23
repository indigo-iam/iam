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
package it.infn.mw.iam.test.api.tokens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.view.TokenApiView;
import org.mitre.openid.connect.view.HttpCodeView;
import org.mitre.openid.connect.view.JsonEntityView;
import org.mitre.openid.connect.view.JsonErrorView;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.ui.ModelMap;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.tokens.UserTokensController;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.ClientRef;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.api.tokens.model.UserRef;
import it.infn.mw.iam.api.tokens.service.TokenService;
import it.infn.mw.iam.persistence.model.IamAccount;

@ExtendWith(MockitoExtension.class)
class UserTokensControllerTests {

  @Mock
  private AccountUtils accountUtils;

  @Mock
  private TokenService<AccessToken> accessTokenService;

  @Mock
  private TokenService<RefreshToken> refreshTokenService;

  @Mock
  private Authentication authentication;

  private UserTokensController controller;

  private IamAccount account;

  @BeforeEach
  void setUp() {

    account = new IamAccount();
    account.setUsername("john");
    controller = new UserTokensController(accountUtils, accessTokenService, refreshTokenService);
  }

  @Test
  void getUserAccessTokens_shouldReturnViewAndPopulateModel() {

    List<AccessToken> tokens = List.of(accessToken(1L, "john"));

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(accessTokenService.getAllTokensForUser("john")).thenReturn(tokens);

    ModelMap model = new ModelMap();

    String result = controller.getUserAccessTokens(authentication, model);

    assertEquals(TokenApiView.VIEWNAME, result);
    assertEquals(tokens, model.get(JsonEntityView.ENTITY));

    verify(accessTokenService).getAllTokensForUser("john");
  }

  @Test
  void getUserRefreshTokens_shouldReturnViewAndPopulateModel() {

    List<RefreshToken> tokens = List.of(refreshToken(1L, "john"));

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(refreshTokenService.getAllTokensForUser("john")).thenReturn(tokens);

    ModelMap model = new ModelMap();

    String result = controller.getUserRefreshTokens(authentication, model);

    assertEquals(TokenApiView.VIEWNAME, result);
    assertEquals(tokens, model.get(JsonEntityView.ENTITY));

    verify(refreshTokenService).getAllTokensForUser("john");
  }

  @Test
  void deleteAccessToken_shouldReturnNotFound_whenTokenDoesNotExist() {

    Long id = 1L;
    ModelMap model = new ModelMap();

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));

    String result = controller.deleteAccessToken(id, authentication, model);

    assertEquals(JsonErrorView.VIEWNAME, result);
    assertEquals(HttpStatus.NOT_FOUND, model.get(HttpCodeView.CODE));
    assertEquals("The requested token with id 1 could not be found.",
        model.get(JsonErrorView.ERROR_MESSAGE));

    verify(accessTokenService, never()).revoke(anyLong());
  }

  @Test
  void deleteAccessToken_shouldReturnForbidden_whenTokenBelongsToAnotherUser() {

    Long id = 1L;

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(accessTokenService.getToken(id)).thenReturn(Optional.of(accessToken(id, "someoneElse")));

    ModelMap model = new ModelMap();

    String result = controller.deleteAccessToken(id, authentication, model);

    assertEquals(JsonErrorView.VIEWNAME, result);
    assertEquals(HttpStatus.FORBIDDEN, model.get(HttpCodeView.CODE));
    assertEquals("You do not have permission to view this token",
        model.get(JsonErrorView.ERROR_MESSAGE));

    verify(accessTokenService, never()).revoke(anyLong());
  }

  @Test
  void deleteAccessToken_shouldRevokeToken_whenOwnerMatches() {

    Long id = 1L;

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(accessTokenService.getToken(id)).thenReturn(Optional.of(accessToken(id, "john")));

    ModelMap model = new ModelMap();

    String result = controller.deleteAccessToken(id, authentication, model);

    assertEquals(HttpCodeView.VIEWNAME, result);

    verify(accessTokenService).revoke(id);
  }

  @Test
  void deleteRefreshToken_shouldReturnNotFound_whenTokenDoesNotExist() {

    Long id = 1L;

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));

    ModelMap model = new ModelMap();

    String result = controller.deleteRefreshToken(id, authentication, model);

    assertEquals(JsonErrorView.VIEWNAME, result);
    assertEquals(HttpStatus.NOT_FOUND, model.get(HttpCodeView.CODE));
    assertEquals("The requested token with id 1 could not be found.",
        model.get(JsonErrorView.ERROR_MESSAGE));

    verify(refreshTokenService, never()).revoke(anyLong());
  }

  @Test
  void deleteRefreshToken_shouldReturnForbidden_whenTokenBelongsToAnotherUser() {

    Long id = 1L;

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(refreshTokenService.getToken(id)).thenReturn(Optional.of(refreshToken(id, "someoneElse")));

    ModelMap model = new ModelMap();

    String result = controller.deleteRefreshToken(id, authentication, model);

    assertEquals(JsonErrorView.VIEWNAME, result);
    assertEquals(HttpStatus.FORBIDDEN, model.get(HttpCodeView.CODE));
    assertEquals("You do not have permission to view this token",
        model.get(JsonErrorView.ERROR_MESSAGE));

    verify(refreshTokenService, never()).revoke(anyLong());
  }

  @Test
  void deleteRefreshToken_shouldRevokeToken_whenOwnerMatches() {

    Long id = 1L;

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(refreshTokenService.getToken(id)).thenReturn(Optional.of(refreshToken(id, "john")));

    ModelMap model = new ModelMap();

    String result = controller.deleteRefreshToken(id, authentication, model);

    assertEquals(HttpCodeView.VIEWNAME, result);

    verify(refreshTokenService).revoke(id);
  }

  @Test
  void shouldThrowException_whenAuthenticatedUserIsMissing() {

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.empty());

    ModelMap model = new ModelMap();

    IllegalStateException ex = assertThrows(IllegalStateException.class,
        () -> controller.getUserAccessTokens(authentication, model));

    assertEquals("Invalid authenticated account", ex.getMessage());
  }

  private AccessToken accessToken(Long id, String username) {

    return new AccessToken(id, "access-token-value", Set.of("openid"), new Date(), "client-id",
        clientRef(), userRef(username), 100L);
  }

  private RefreshToken refreshToken(Long id, String username) {

    return new RefreshToken(id, "refresh-token-value", new Date(), Set.of("openid"), "client-id",
        clientRef(), userRef(username));
  }

  private UserRef userRef(String username) {

    return new UserRef("user-id", username, "/Users/user-id");
  }

  private ClientRef clientRef() {

    return new ClientRef(1L, "client-id", "Test Client", Set.of("admin@example.com"), "/Clients/1");
  }
}
