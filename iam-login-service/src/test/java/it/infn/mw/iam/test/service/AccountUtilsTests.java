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

import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
@RunWith(MockitoJUnitRunner.class)
public class AccountUtilsTests {

  @Mock
  IamAccountRepository repo;

  @Mock
  SecurityContext securityContext;

  @Mock
  IamAccount account;
  
  @InjectMocks
  AccountUtils utils;

  @Before
  public void setup() {
    SecurityContextHolder.clearContext();
  }
 

  @Test
  public void isAuthenticatedReturnsFalseForAnonymousAuthenticationToken() {
    AnonymousAuthenticationToken anonymousToken = Mockito.mock(AnonymousAuthenticationToken.class);
    when(securityContext.getAuthentication()).thenReturn(anonymousToken);
    SecurityContextHolder.setContext(securityContext);

    assertThat(utils.isAuthenticated(), is(false));
  }
  
  @Test
  public void isAuthenticatedReturnsFalseForNullAuthentication() {
    SecurityContextHolder.createEmptyContext();
    assertThat(utils.isAuthenticated(), is(false));
  }
  
  @Test
  public void isAuthenticatedReturnsTrueForUsernamePasswordAuthenticationToken() {
    UsernamePasswordAuthenticationToken token = Mockito.mock(UsernamePasswordAuthenticationToken.class);

    when(securityContext.getAuthentication()).thenReturn(token);
    SecurityContextHolder.setContext(securityContext);
    assertThat(utils.isAuthenticated(), is(true));
  }
  
  @Test
  public void getAuthenticatedUserAccountReturnsEmptyOptionalForNullSecurityContext() {
    assertThat(utils.getAuthenticatedUserAccount().isPresent(), is(false)); 
  }
  
  @Test
  public void getAuthenticatedUserAccountReturnsEmptyOptionalForAnonymousSecurityContext() {
    AnonymousAuthenticationToken anonymousToken = Mockito.mock(AnonymousAuthenticationToken.class);
    when(securityContext.getAuthentication()).thenReturn(anonymousToken);
    SecurityContextHolder.setContext(securityContext);
    assertThat(utils.getAuthenticatedUserAccount().isPresent(), is(false)); 
  }
  
  @Test
  public void getAuthenticatedUserAccountWorksForUsernamePasswordAuthenticationToken() {
    when(account.getUsername()).thenReturn("test");
    when(repo.findByUsername("test")).thenReturn(Optional.of(account));
    
    UsernamePasswordAuthenticationToken token = Mockito.mock(UsernamePasswordAuthenticationToken.class);
    when(token.getName()).thenReturn("test");
    when(securityContext.getAuthentication()).thenReturn(token);
    SecurityContextHolder.setContext(securityContext);
    
    Optional<IamAccount> authUserAccount = utils.getAuthenticatedUserAccount();
    assertThat(authUserAccount.isPresent(), is(true));
    assertThat(authUserAccount.get().getUsername(), equalTo("test"));
    
  }
  
  @Test
  public void getAuthenticatedUserAccountWorksForOauthToken() {
    when(account.getUsername()).thenReturn("test");
    when(repo.findByUsername("test")).thenReturn(Optional.of(account));
    
    UsernamePasswordAuthenticationToken token = Mockito.mock(UsernamePasswordAuthenticationToken.class);
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
  public void getAuthenticatedUserAccountReturnsEmptyOptionalForClientOAuthToken() {
    OAuth2Authentication oauth = Mockito.mock(OAuth2Authentication.class);

    when(oauth.getUserAuthentication()).thenReturn(null);
    when(securityContext.getAuthentication()).thenReturn(oauth);
    SecurityContextHolder.setContext(securityContext);
    
    assertThat(utils.getAuthenticatedUserAccount().isPresent(), is(false)); 
  }
}
