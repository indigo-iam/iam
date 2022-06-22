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
package it.infn.mw.iam.test.api.aup;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.AUPSignatureCheckService;
import it.infn.mw.iam.authn.EnforceAupSignatureSuccessHandler;
import it.infn.mw.iam.core.web.aup.EnforceAupFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
@RunWith(MockitoJUnitRunner.class)
public class EnforceAupSignatureSuccessHandlerTests {

  @Mock
  AuthenticationSuccessHandler delegate;
  
  @Mock
  AUPSignatureCheckService signatureCheckService;
  
  @Mock
  AccountUtils accountUtils;
  
  @Mock
  IamAccountRepository accountRepo;
  
  @Mock
  HttpServletRequest request;
  
  @Mock
  HttpServletResponse response;
  
  @Mock
  HttpSession session;
  
  @Mock
  Authentication auth;
  
  @Mock
  IamAccount account;
  
  
  @InjectMocks
  EnforceAupSignatureSuccessHandler handler;
  
  
  @Before
  public void before() {
    when(request.getSession(false)).thenReturn(session);
    when(request.getSession()).thenReturn(session);
    
    when(auth.getName()).thenReturn("test");
    
  }
  
  @Test
  public void userIsRedirectedToSignAupPageWhenNeeded() throws IOException, ServletException {
    // when(accountUtils.getAuthenticatedUserAccount()).thenReturn(Optional.of(account));
    when(accountUtils.getAuthenticatedUserAccount(Mockito.any())).thenReturn(Optional.of(account));
    when(signatureCheckService.needsAupSignature(Mockito.any())).thenReturn(true);
   
    handler.onAuthenticationSuccess(request, response, auth);
    verify(session).setAttribute(Mockito.eq(AuthenticationTimeStamper.AUTH_TIMESTAMP), Mockito.any());
    verify(session).setAttribute(Mockito.eq(EnforceAupFilter.REQUESTING_SIGNATURE), Mockito.eq(true));
    verify(accountRepo).touchLastLoginTimeForUserWithUsername(Mockito.eq("test"));
    verify(response).sendRedirect(Mockito.eq("/iam/aup/sign"));
  }

  @Test
  public void delegateIsCalledIfNoSignatureIsNeeded()throws IOException, ServletException {
    // when(accountUtils.getAuthenticatedUserAccount()).thenReturn(Optional.of(account));
    when(accountUtils.getAuthenticatedUserAccount(Mockito.any())).thenReturn(Optional.of(account));
    when(signatureCheckService.needsAupSignature(Mockito.any())).thenReturn(false); 
    
    handler.onAuthenticationSuccess(request, response, auth);
    verify(session).setAttribute(Mockito.eq(AuthenticationTimeStamper.AUTH_TIMESTAMP), Mockito.any());
    verify(delegate).onAuthenticationSuccess(Mockito.eq(request), Mockito.eq(response), Mockito.eq(auth));
    verify(accountRepo).touchLastLoginTimeForUserWithUsername(Mockito.eq("test"));
  }
 
  
  @Test
  public void testOAuthAuthenticationIsUnderstood() throws IOException, ServletException {
    OAuth2Authentication oauth = Mockito.mock(OAuth2Authentication.class);
    when(oauth.getName()).thenReturn("oauth-client-for-test");
    when(oauth.getUserAuthentication()).thenReturn(auth);
    
    // when(accountUtils.getAuthenticatedUserAccount()).thenReturn(Optional.of(account));
    when(accountUtils.getAuthenticatedUserAccount(Mockito.any())).thenReturn(Optional.of(account));
    when(signatureCheckService.needsAupSignature(Mockito.any())).thenReturn(false);
    
    handler.onAuthenticationSuccess(request, response, oauth);
    verify(session).setAttribute(Mockito.eq(AuthenticationTimeStamper.AUTH_TIMESTAMP), Mockito.any());
    verify(delegate).onAuthenticationSuccess(Mockito.eq(request), Mockito.eq(response), Mockito.eq(oauth));
    verify(accountRepo).touchLastLoginTimeForUserWithUsername(Mockito.eq("test")); 
  }
  
  @Test
  public void testOAuthClientAuthenticationDoesNotResultInUserLoginTimeUpdate() throws IOException, ServletException {
    OAuth2Authentication oauth = Mockito.mock(OAuth2Authentication.class);
    when(oauth.getName()).thenReturn("oauth-client-for-test");
    when(oauth.getUserAuthentication()).thenReturn(null);
    // when(signatureCheckService.needsAupSignature(Mockito.any())).thenReturn(false);
    
    // when(accountUtils.getAuthenticatedUserAccount()).thenReturn(Optional.empty());
    // when(accountUtils.getAuthenticatedUserAccount(Mockito.any())).thenReturn(Optional.empty());
    
    handler.onAuthenticationSuccess(request, response, oauth);
    verify(session).setAttribute(Mockito.eq(AuthenticationTimeStamper.AUTH_TIMESTAMP), Mockito.any());
    verify(delegate).onAuthenticationSuccess(Mockito.eq(request), Mockito.eq(response), Mockito.eq(oauth));
    verify(accountRepo, Mockito.never()).touchLastLoginTimeForUserWithUsername(Mockito.anyString()); 
  }
  
}
