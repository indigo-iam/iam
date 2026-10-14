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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedUserException;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.tokens.UserTokensController;
import it.infn.mw.iam.api.tokens.exception.TokenNotFoundException;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.ClientRef;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.api.tokens.model.UserRef;
import it.infn.mw.iam.api.tokens.service.TokenService;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
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
  void getUserAccessTokensShouldReturnAccessTokenList() {

    List<AccessToken> tokens = List.of(accessToken(1L, "john"));

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(accessTokenService.getAllTokensForUser("john")).thenReturn(tokens);

    List<AccessToken> result = controller.getUserAccessTokens(authentication);

    assertEquals(1, result.size());

    verify(accessTokenService).getAllTokensForUser("john");
  }

  @Test
  void getUserRefreshTokensShouldReturnRefreshTokenList() {

    List<RefreshToken> tokens = List.of(refreshToken(1L, "john"));

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(refreshTokenService.getAllTokensForUser("john")).thenReturn(tokens);

    List<RefreshToken> result = controller.getUserRefreshTokens(authentication);

    assertEquals(1, result.size());

    verify(refreshTokenService).getAllTokensForUser("john");
  }

  @Test
  void deleteAccessTokenShouldReturnTokenNotFoundExceptionWhenDoesNotExist() {

    Long id = 1L;

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));

    TokenNotFoundException e = assertThrows(TokenNotFoundException.class,
        () -> controller.deleteAccessToken(id, authentication));
    assertEquals("The requested token with id 1 could not be found.", e.getMessage());

    verify(accessTokenService, never()).revoke(anyLong());
  }

  @Test
  void deleteAccessTokenShouldReturnForbiddenWhenTokenBelongsToAnotherUser() {

    Long id = 1L;

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(accessTokenService.getToken(id)).thenReturn(Optional.of(accessToken(id, "someoneElse")));

    UnauthorizedUserException e = assertThrows(UnauthorizedUserException.class,
        () -> controller.deleteAccessToken(id, authentication));
    assertEquals("You do not have permission to view this token", e.getMessage());

    verify(accessTokenService, never()).revoke(anyLong());
  }

  @Test
  void deleteAccessTokenShouldRevokeTokenWhenOwnerMatches() {

    Long id = 1L;

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(accessTokenService.getToken(id)).thenReturn(Optional.of(accessToken(id, "john")));

    controller.deleteAccessToken(id, authentication);

    verify(accessTokenService).revoke(id);
  }

  @Test
  void deleteRefreshTokenShouldReturnTokenNotFoundExceptionWhenTokenDoesNotExist() {

    Long id = 1L;

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));

    TokenNotFoundException e = assertThrows(TokenNotFoundException.class,
        () -> controller.deleteRefreshToken(id, authentication));

    assertEquals("The requested token with id 1 could not be found.", e.getMessage());

    verify(refreshTokenService, never()).revoke(anyLong());
  }

  @Test
  void deleteRefreshTokenShouldReturnForbiddenWhenTokenBelongsToAnotherUser() {

    Long id = 1L;

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(refreshTokenService.getToken(id)).thenReturn(Optional.of(refreshToken(id, "someoneElse")));

    UnauthorizedUserException e = assertThrows(UnauthorizedUserException.class,
        () -> controller.deleteRefreshToken(id, authentication));

    assertEquals("You do not have permission to view this token", e.getMessage());

    verify(refreshTokenService, never()).revoke(anyLong());
  }

  @Test
  void deleteRefreshTokenShouldRevokeTokenWhenOwnerMatches() {

    Long id = 1L;

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.of(account));
    when(refreshTokenService.getToken(id)).thenReturn(Optional.of(refreshToken(id, "john")));

    controller.deleteRefreshToken(id, authentication);

    verify(refreshTokenService).revoke(id);
  }

  @Test
  void shouldThrowExceptionWhenAuthenticatedUserIsMissing() {

    when(accountUtils.getAuthenticatedUserAccount(authentication)).thenReturn(Optional.empty());

    IllegalStateException ex = assertThrows(IllegalStateException.class,
        () -> controller.getUserAccessTokens(authentication));

    assertEquals("Invalid authenticated account", ex.getMessage());
  }

  private AccessToken accessToken(Long id, String username) {

    return new AccessToken(id, Set.of("https://localhost:8080/"), Set.of("openid"), new Date(),
        "client-id", clientRef(), userRef(username), 100L);
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
