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
package it.infn.mw.iam.authn;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class ExternalAuthenticationSuccessHandler extends ExternalAuthenticationHandlerSupport
    implements AuthenticationSuccessHandler {

  private final AuthenticationSuccessHandler delegate;
  private final String unregisteredUserTargetURL;

  public ExternalAuthenticationSuccessHandler(AuthenticationSuccessHandler delegate,
      String unregisteredUserTargetURL) {
    this.delegate = delegate;
    this.unregisteredUserTargetURL = unregisteredUserTargetURL;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {

    if (hasOngoingAccountLinking(request)) {

      HttpSession session = request.getSession();

      saveExternalAuthenticationInSession(session, authentication);
      restoreSavedAuthentication(session);
      setAccountLinkingDone(session);

      request.getRequestDispatcher(getAccountLinkingForwardTarget(request)).forward(request,
          response);

    } else {

      if (isExternalUnregisteredUser(authentication)) {
        response.sendRedirect(unregisteredUserTargetURL);

      } else {
        delegate.onAuthenticationSuccess(request, response, authentication);
      }

    }
  }

}
