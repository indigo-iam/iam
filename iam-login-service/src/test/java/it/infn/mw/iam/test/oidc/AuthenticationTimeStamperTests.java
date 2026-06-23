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
package it.infn.mw.iam.test.oidc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import it.infn.mw.iam.core.oidc.AuthenticationTimeStamper;
import it.infn.mw.iam.core.oidc.PromptService;

class AuthenticationTimeStamperTests {

  @Test
  void setsAuthenticationTimestampOnSession() throws Exception {
    AuthenticationTimeStamper stamper = new AuthenticationTimeStamper();

    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession session = mock(HttpSession.class);
    Authentication authentication = mock(Authentication.class);

    when(request.getSession()).thenReturn(session);
    when(authentication.getName()).thenReturn("test-user");

    stamper.onAuthenticationSuccess(request, response, authentication);

    verify(session).setAttribute(
        eq(AuthenticationTimeStamper.AUTH_TIMESTAMP),
        argThat(value -> value instanceof java.util.Date));

    verify(session, never()).setAttribute(eq(PromptService.PROMPTED), any());
    verify(session, never()).removeAttribute(PromptService.PROMPT_REQUESTED);
  }

  @Test
  void marksPromptedWhenPromptWasRequested() throws Exception {
    AuthenticationTimeStamper stamper = new AuthenticationTimeStamper();

    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession session = mock(HttpSession.class);
    Authentication authentication = mock(Authentication.class);

    when(request.getSession()).thenReturn(session);
    when(authentication.getName()).thenReturn("test-user");
    when(session.getAttribute(PromptService.PROMPT_REQUESTED)).thenReturn(Boolean.TRUE);

    stamper.onAuthenticationSuccess(request, response, authentication);

    verify(session).setAttribute(eq(PromptService.PROMPTED), eq(Boolean.TRUE));
    verify(session).removeAttribute(PromptService.PROMPT_REQUESTED);
  }
}