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
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

public class ExternalAuthenticationFailureHandler extends ExternalAuthenticationHandlerSupport
    implements AuthenticationFailureHandler {

  private static final Logger LOG =
      LoggerFactory.getLogger(ExternalAuthenticationFailureHandler.class);

  private final AuthenticationExceptionMessageHelper helper;

  public ExternalAuthenticationFailureHandler(AuthenticationExceptionMessageHelper errorHelper) {
    this.helper = errorHelper;
  }

  private String buildRedirectURL(AuthenticationException exception) {
    String errorMessage = helper.buildErrorMessage(exception);

    errorMessage = UriUtils.encode(errorMessage, StandardCharsets.UTF_8.toString());

    return UriComponentsBuilder.fromPath("/login")
      .queryParam("error", "true")
      .queryParam("externalAuthenticationError", errorMessage)
      .build(true)
      .toString();
  }

  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) throws IOException, ServletException {

    String errorMessage = exception.getMessage();

    if (exception.getCause() != null) {
      errorMessage = exception.getCause().getMessage();
    }

    LOG.info("External authentication failure: {}", errorMessage, exception);

    saveAuthenticationErrorInSession(request, exception);

    if (hasOngoingAccountLinking(request)) {

      restoreSavedAuthentication(request.getSession());

      clearAccountLinkingSessionAttributes(request.getSession());

      response.sendRedirect("/dashboard");
      return;
    }

    response.sendRedirect(buildRedirectURL(exception));

  }

}
