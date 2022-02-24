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
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import it.infn.mw.iam.core.ExtendedAuthenticationToken;

public class MultiFactorVerificationFilter extends AbstractAuthenticationProcessingFilter {

  public static final String TOTP_MFA_CODE_KEY = "code";
  public static final String MULTI_FACTOR_VERIFIED = "MULTI_FACTOR_VERIFIED";

  private final boolean postOnly = true;
  private AuthenticationManager authenticationManager;

  private ExtendedAuthenticationToken token;
  private String codeParameter = TOTP_MFA_CODE_KEY;
  private AuthenticationSuccessHandler authenticationSuccessHandler;

  public MultiFactorVerificationFilter(AuthenticationManager authenticationManager) {
    super("/iam/verify", authenticationManager);
    this.authenticationManager = authenticationManager;
  }

  public void setAuthenticationSuccessHandler(
      AuthenticationSuccessHandler authenticationSuccessHandler) {
    this.authenticationSuccessHandler = authenticationSuccessHandler;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    Object multiFactorVerifiedAttribute = request.getAttribute(MULTI_FACTOR_VERIFIED);

    if (multiFactorVerifiedAttribute == null) {
      HttpServletRequest httpServletRequest = (HttpServletRequest) request;
      if (httpServletRequest.getMethod().equals("POST")
          && httpServletRequest.getRequestURI().equals("/iam/verify")) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth instanceof ExtendedAuthenticationToken && isMfaEnabled(auth)) {
          token = (ExtendedAuthenticationToken) auth;
          HttpServletResponse httpServletResponse = (HttpServletResponse) response;

          Authentication newAuth = attemptAuthentication(httpServletRequest, httpServletResponse);
          SecurityContextHolder.getContext().setAuthentication(newAuth);

          request.setAttribute(MULTI_FACTOR_VERIFIED, Boolean.TRUE);
          authenticationSuccessHandler.onAuthenticationSuccess(httpServletRequest,
              httpServletResponse, newAuth);
        }
      }
    }

    chain.doFilter(request, response);
  }

  private boolean isMfaEnabled(final Authentication authentication) {
    final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
    for (final GrantedAuthority grantedAuthority : authorities) {
      String authorityName = grantedAuthority.getAuthority();
      if (authorityName.equals("ROLE_PRE_AUTHENTICATED")) {
        return true;
      }
    }

    return false;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    if (this.postOnly && !request.getMethod().equals("POST")) {
      throw new AuthenticationServiceException(
          "Authentication method not supported: " + request.getMethod());
    }

    if (this.token == null) {
      return null;
    }

    String code = request.getParameter(this.codeParameter);
    code = (code != null) ? code : "";
    code = code.trim();

    ExtendedAuthenticationToken authRequest = new ExtendedAuthenticationToken(this.token);
    authRequest.setCode(code);

    return this.authenticationManager.authenticate(authRequest);
  }
}
