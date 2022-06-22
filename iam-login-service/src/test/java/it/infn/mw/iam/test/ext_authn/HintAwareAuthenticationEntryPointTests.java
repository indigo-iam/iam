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
package it.infn.mw.iam.test.ext_authn;

import static it.infn.mw.iam.authn.HintAwareAuthenticationEntryPoint.EXT_AUTHN_HINT_PARAM;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import it.infn.mw.iam.authn.ExternalAuthenticationHintService;
import it.infn.mw.iam.authn.HintAwareAuthenticationEntryPoint;

@RunWith(MockitoJUnitRunner.class)
public class HintAwareAuthenticationEntryPointTests {

  public static final String BASE_URL = "";
  public static final String AUTHORIZE_URL = String.format("%s/authorize", BASE_URL);

  @Mock
  ExternalAuthenticationHintService hintService;

  @Mock
  HttpServletRequest request;

  @Mock
  HttpServletResponse response;

  @Mock
  AuthenticationException exception;

  @Mock
  AuthenticationEntryPoint delegateEntryPoint;

  @InjectMocks
  HintAwareAuthenticationEntryPoint entryPoint;

  @Before
  public void before() {
    // when(request.getContextPath()).thenReturn("");
  }

  @Test
  public void nonAuthorizeRequestIsPassedToDelegateEntryPoint() throws IOException, ServletException {
    when(request.getRequestURI()).thenReturn(BASE_URL);
    entryPoint.commence(request, response, exception);
    verify(delegateEntryPoint, times(1)).commence(request, response, exception);
  }
  
  @Test
  public void authorizeRequestWithoutHintIsPassedToDelegateEntryPoint() throws IOException, ServletException {
    when(request.getRequestURI()).thenReturn(AUTHORIZE_URL);
    entryPoint.commence(request, response, exception);
    verify(delegateEntryPoint, times(1)).commence(request, response, exception);
  }
  
  @Test
  public void authorizeRequestWithHintIsUnderstood() throws IOException, ServletException {
    when(request.getRequestURI()).thenReturn(AUTHORIZE_URL);
    when(request.getParameter(EXT_AUTHN_HINT_PARAM)).thenReturn("saml:exampleEntity");
    when(hintService.resolve(anyString())).thenReturn("/saml/login?idp=exampleEntity");
    entryPoint.commence(request, response, exception);
    verify(delegateEntryPoint, times(0)).commence(request, response, exception);
    verify(hintService, times(1)).resolve(eq("saml:exampleEntity"));
    verify(response, times(1)).sendRedirect(eq("/saml/login?idp=exampleEntity"));
  }
}
