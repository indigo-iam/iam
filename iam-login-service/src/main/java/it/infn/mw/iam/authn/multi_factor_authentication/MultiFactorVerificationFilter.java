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

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;

import java.io.IOException;
import java.nio.file.ProviderNotFoundException;

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

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;

/**
 * Used in the MFA verification flow. Receives either a TOTP and constructs the authentication
 * request with this parameter. The request is passed to dedicated authentication providers which
 * will create the full authentication or raise the appropriate exception
 */
public class MultiFactorVerificationFilter extends AbstractAuthenticationProcessingFilter {

  public static final String TOTP_MFA_CODE_KEY = "totp";
  public static final String TOTP_VERIFIED = "TOTP_VERIFIED";

  public static final AntPathRequestMatcher DEFAULT_MFA_VERIFY_ANT_PATH_REQUEST_MATCHER =
      new AntPathRequestMatcher(MFA_VERIFY_URL, "POST");

  private static final boolean postOnly = true;

  private String totpParameter = TOTP_MFA_CODE_KEY;

  public MultiFactorVerificationFilter(AuthenticationManager authenticationManager,
      AuthenticationSuccessHandler successHandler, AuthenticationFailureHandler failureHandler) {
    super(DEFAULT_MFA_VERIFY_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    setAuthenticationSuccessHandler(successHandler);
    setAuthenticationFailureHandler(failureHandler);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    if (postOnly && !request.getMethod().equals("POST")) {
      throw new AuthenticationServiceException(
          "Authentication method not supported: " + request.getMethod());
    }

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (!(auth instanceof ExtendedAuthenticationToken)
        && !(auth instanceof AbstractExternalAuthenticationToken)) {
      throw new AuthenticationServiceException("Bad authentication");
    }

    return processTotpAuthentication(auth, request);
  }

  private Authentication processTotpAuthentication(Authentication auth,
      HttpServletRequest request) {
    // Parse TOTP from request (only one should be set)
    String totp = parseTotp(request);
    if (totp == null) {
      throw new ProviderNotFoundException("No valid TOTP code was received");
    }

    if (auth instanceof ExtendedAuthenticationToken extendedAuthenticationToken) {
      extendedAuthenticationToken.setTotp(totp);
    } else if (auth instanceof AbstractExternalAuthenticationToken externalAuthenticationToken) {
      externalAuthenticationToken.setTotp(totp);
    }

    Authentication fullAuthentication = getAuthenticationManager().authenticate(auth);
    if (fullAuthentication == null) {
      throw new ProviderNotFoundException("No valid TOTP code was received");
    }

    request.setAttribute(TOTP_VERIFIED, Boolean.TRUE);
    return fullAuthentication;
  }

  /**
   * Overriding default method because we don't want to invalidate authentication. Doing so would
   * remove our PRE_AUTHENTICATED role, which would kick us out of the verification process
   */
  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request,
      HttpServletResponse response, AuthenticationException failed)
      throws IOException, ServletException {
    this.logger.trace("Failed to process authentication request", failed);
    this.logger.trace("Handling authentication failure");
    this.getRememberMeServices().loginFail(request, response);
    this.getFailureHandler().onAuthenticationFailure(request, response, failed);
  }

  private String parseTotp(HttpServletRequest request) {
    String totp = request.getParameter(this.totpParameter);
    return totp != null ? totp.trim() : null;
  }

}
