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
import java.util.Objects;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

public class HintAwareAuthenticationEntryPoint implements AuthenticationEntryPoint {

  public static final String EXT_AUTHN_HINT_PARAM = "ext_authn_hint";

  private final AuthenticationEntryPoint delegate;
  private final ExternalAuthenticationHintService hintService;

  public HintAwareAuthenticationEntryPoint(AuthenticationEntryPoint delegate,
      ExternalAuthenticationHintService service) {
    this.delegate = delegate;
    this.hintService = service;
  }

  protected boolean isOAuthAuthorizationRequestWithHint(HttpServletRequest request) {

    boolean isAuthorizeRequest = "/authorize".equals(request.getRequestURI()); 
    String hintParam = request.getParameter(EXT_AUTHN_HINT_PARAM);
    return isAuthorizeRequest && !Objects.isNull(hintParam);

  }

  protected void handleExternalAuthenticationHint(HttpServletRequest request,
      HttpServletResponse response) throws IOException {

    String redirectUrl = hintService.resolve(request.getParameter(EXT_AUTHN_HINT_PARAM));
    response.sendRedirect(redirectUrl);
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {

    if (isOAuthAuthorizationRequestWithHint(request)) {
      handleExternalAuthenticationHint(request, response);
      return;
    }

    delegate.commence(request, response, authException);
  }

}
