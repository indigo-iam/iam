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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import it.infn.mw.iam.core.ExtendedAuthenticationToken;

/**
 * This replaces the default {@code UsernamePasswordAuthenticationFilter}. It is used to store a new
 * {@code ExtendedAuthenticationToken} into the security context instead of a
 * {@code UsernamePasswordAuthenticationToken}.
 * 
 * <p>
 * Ultimately, we want to store information about the methods of authentication used for every login
 * attempt. This is useful for registered clients, who may wish to restrict access to certain users
 * based on the type or quantity of authentication methods used. The authentication methods are
 * passed to the OAuth2 authorization endpoint and stored in the id_token returned to the client.
 */
public class ExtendedAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private boolean postOnly = true;
  private AuthenticationManager authenticationManager;

  public ExtendedAuthenticationFilter(AuthenticationManager authenticationManager,
      AuthenticationSuccessHandler successHandler) {
    this.authenticationManager = authenticationManager;
    this.setAuthenticationSuccessHandler(successHandler);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {

    if (this.postOnly && !request.getMethod().equals("POST")) {
      throw new AuthenticationServiceException(
          "Authentication method not supported: " + request.getMethod());
    }
    String username = obtainUsername(request);
    username = (username != null) ? username : "";
    username = username.trim();
    String password = obtainPassword(request);
    password = (password != null) ? password : "";

    ExtendedAuthenticationToken authRequest = new ExtendedAuthenticationToken(username, password);
    // Allow subclasses to set the "details" property
    setDetails(request, authRequest);
    return this.authenticationManager.authenticate(authRequest);
  }

  private void setDetails(HttpServletRequest request, ExtendedAuthenticationToken authRequest) {
    authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
  }
}
