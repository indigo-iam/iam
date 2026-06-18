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
package it.infn.mw.iam.test.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class AccountUtilsTests {

  @Mock
  IamAccountRepository repo;

  @Mock
  SecurityContext securityContext;

  @Mock
  IamAccount account;

  @InjectMocks
  AccountUtils utils;

  @BeforeEach
  void setup() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void isAuthenticatedReturnsFalseForAnonymousAuthenticationToken() {

    AnonymousAuthenticationToken anonymousToken = Mockito.mock(AnonymousAuthenticationToken.class);
    when(securityContext.getAuthentication()).thenReturn(anonymousToken);
    SecurityContextHolder.setContext(securityContext);
    assertThat(utils.isAuthenticated(), is(false));
  }

  @Test
  void isAuthenticatedReturnsFalseForNullAuthentication() {

    SecurityContextHolder.createEmptyContext();
    assertThat(utils.isAuthenticated(), is(false));
  }

  @Test
  void isAuthenticatedReturnsTrueForUsernamePasswordAuthenticationToken() {

    UsernamePasswordAuthenticationToken token =
        Mockito.mock(UsernamePasswordAuthenticationToken.class);
    when(securityContext.getAuthentication()).thenReturn(token);
    SecurityContextHolder.setContext(securityContext);
    assertThat(utils.isAuthenticated(), is(true));
  }

  @Test
  void isAuthenticatedReturnsFalseForExtendedAuthenticationToken() {

    ExtendedAuthenticationToken token = Mockito.mock(ExtendedAuthenticationToken.class);
    when(securityContext.getAuthentication()).thenReturn(token);
    SecurityContextHolder.setContext(securityContext);
    assertThat(utils.isAuthenticated(), is(false));
  }

  @Test
  void isPreAuthenticatedReturnsFalseForNullAuthentication() {

    SecurityContextHolder.createEmptyContext();
    assertThat(utils.isPreAuthenticated(null), is(false));
  }

  @Test
  void isPreAuthenticatedReturnsFalseForEmptyAuthorities() {

    UsernamePasswordAuthenticationToken token =
        Mockito.mock(UsernamePasswordAuthenticationToken.class);

    assertThat(utils.isPreAuthenticated(token), is(false));
  }

  @Test
  void isPreAuthenticatedReturnsTrueForProperAuthority() {

    UsernamePasswordAuthenticationToken token =
        Mockito.mock(UsernamePasswordAuthenticationToken.class);

    when(token.getAuthorities())
      .thenReturn(Collections.singleton(Authorities.ROLE_PRE_AUTHENTICATED));
    assertThat(utils.isPreAuthenticated(token), is(true));
  }

  @Test
  void getAuthenticatedUserAccountReturnsEmptyOptionalForNullSecurityContext() {

    assertThat(utils.getAuthenticatedUserAccount().isPresent(), is(false));
  }

  @Test
  void getAuthenticatedUserAccountReturnsEmptyOptionalForAnonymousSecurityContext() {

    AnonymousAuthenticationToken anonymousToken = Mockito.mock(AnonymousAuthenticationToken.class);
    when(securityContext.getAuthentication()).thenReturn(anonymousToken);
    SecurityContextHolder.setContext(securityContext);
    assertThat(utils.getAuthenticatedUserAccount().isPresent(), is(false));
  }

  @Test
  void getAuthenticatedUserAccountWorksForUsernamePasswordAuthenticationToken() {

    when(account.getUsername()).thenReturn("test");
    when(repo.findByUsername("test")).thenReturn(Optional.of(account));

    UsernamePasswordAuthenticationToken token =
        Mockito.mock(UsernamePasswordAuthenticationToken.class);
    when(token.getName()).thenReturn("test");
    when(securityContext.getAuthentication()).thenReturn(token);
    SecurityContextHolder.setContext(securityContext);

    Optional<IamAccount> authUserAccount = utils.getAuthenticatedUserAccount();
    assertThat(authUserAccount.isPresent(), is(true));
    assertThat(authUserAccount.get().getUsername(), equalTo("test"));
  }

  @Test
  void getAuthenticatedUserAccountWorksForOauthToken() {

    when(account.getUsername()).thenReturn("test");
    when(repo.findByUsername("test")).thenReturn(Optional.of(account));

    UsernamePasswordAuthenticationToken token =
        Mockito.mock(UsernamePasswordAuthenticationToken.class);
    when(token.getName()).thenReturn("test");

    OAuth2Authentication oauth = Mockito.mock(OAuth2Authentication.class);

    when(oauth.getUserAuthentication()).thenReturn(token);

    when(securityContext.getAuthentication()).thenReturn(oauth);
    SecurityContextHolder.setContext(securityContext);

    Optional<IamAccount> authUserAccount = utils.getAuthenticatedUserAccount();
    assertThat(authUserAccount.isPresent(), is(true));
    assertThat(authUserAccount.get().getUsername(), equalTo("test"));
  }

  @Test
  void getAuthenticatedUserAccountReturnsEmptyOptionalForClientOAuthToken() {

    OAuth2Authentication oauth = Mockito.mock(OAuth2Authentication.class);

    when(oauth.getUserAuthentication()).thenReturn(null);
    when(securityContext.getAuthentication()).thenReturn(oauth);
    SecurityContextHolder.setContext(securityContext);
    assertThat(utils.getAuthenticatedUserAccount().isPresent(), is(false));
  }
}
