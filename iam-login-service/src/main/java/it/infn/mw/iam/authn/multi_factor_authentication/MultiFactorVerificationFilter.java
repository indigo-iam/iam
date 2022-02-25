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
package it.infn.mw.iam.authn.multi_factor_authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import it.infn.mw.iam.core.ExtendedAuthenticationToken;

public class MultiFactorVerificationFilter extends AbstractAuthenticationProcessingFilter {

  public static final String TOTP_MFA_CODE_KEY = "code";
  public static final String MULTI_FACTOR_VERIFIED = "MULTI_FACTOR_VERIFIED";

  private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER =
      new AntPathRequestMatcher("/iam/verify", "POST");

  private final boolean postOnly = true;

  private String codeParameter = TOTP_MFA_CODE_KEY;

  public MultiFactorVerificationFilter(AuthenticationManager authenticationManager,
      AuthenticationSuccessHandler successHandler, AuthenticationFailureHandler failureHandler) {
    super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    setAuthenticationSuccessHandler(successHandler);
    setAuthenticationFailureHandler(failureHandler);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    if (this.postOnly && !request.getMethod().equals("POST")) {
      throw new AuthenticationServiceException(
          "Authentication method not supported: " + request.getMethod());
    }

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth == null || !(auth instanceof ExtendedAuthenticationToken)) {
      throw new AuthenticationServiceException("Bad authentication");
    }

    String code = request.getParameter(this.codeParameter);
    code = (code != null) ? code : "";
    code = code.trim();

    ExtendedAuthenticationToken authRequest = (ExtendedAuthenticationToken) auth;
    authRequest.setCode(code);

    return this.getAuthenticationManager().authenticate(authRequest);
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request,
      HttpServletResponse response, AuthenticationException failed)
      throws IOException, ServletException {
    this.logger.trace("Failed to process authentication request", failed);
    this.logger.trace("Handling authentication failure");
    this.getRememberMeServices().loginFail(request, response);
    this.getFailureHandler().onAuthenticationFailure(request, response, failed);
  }
}
