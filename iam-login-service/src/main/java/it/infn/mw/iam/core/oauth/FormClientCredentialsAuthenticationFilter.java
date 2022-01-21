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
package it.infn.mw.iam.core.oauth;

import static com.google.common.base.Strings.isNullOrEmpty;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import it.infn.mw.iam.core.ExtendedAuthenticationToken;

public class FormClientCredentialsAuthenticationFilter
    extends AbstractAuthenticationProcessingFilter {

  private final AuthenticationEntryPoint authenticationEntryPoint;

  public FormClientCredentialsAuthenticationFilter(String pattern, AuthenticationEntryPoint aep) {
    super(new AntPathRequestMatcher(pattern));
    this.authenticationEntryPoint = aep;
    setAuthenticationFailureHandler(authenticationEntryPoint::commence);
    setContinueChainBeforeSuccessfulAuthentication(true);
    setAuthenticationSuccessHandler((req, res, a) -> {
    });
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws IOException, ServletException {

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null && authentication.isAuthenticated()) {
      return authentication;
    }

    String clientId = request.getParameter("client_id");
    String clientSecret = request.getParameter("client_secret");

    if (isNullOrEmpty(clientId)) {
      throw new InsufficientAuthenticationException("No client credentials found in request");
    }

    ExtendedAuthenticationToken authRequest =
        new ExtendedAuthenticationToken(clientId.trim(), clientSecret);

    return this.getAuthenticationManager().authenticate(authRequest);
  }

}
