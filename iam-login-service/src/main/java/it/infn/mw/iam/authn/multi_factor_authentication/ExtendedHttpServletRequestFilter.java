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
import java.util.Iterator;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import it.infn.mw.iam.core.ExtendedAuthenticationToken;

/**
 * This filter is applied after authentication has taken place. It is used in the OAuth2 process to
 * detect if a set of {@code IamAuthenticationMethodReference} objects are included in the current
 * {@code Authentication} object. If so, these are passed to an {@code ExtendedHttpServletRequest}
 * so they may be included in the authorization request and passed to OAuth2 clients.
 */
public class ExtendedHttpServletRequestFilter extends GenericFilterBean {

  public static final String AUTHORIZATION_REQUEST_INCLUDES_AMR =
      "AUTHORIZATION_REQUEST_INCLUDES_AMR";

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {

    // We fetch the ExtendedAuthenticationToken from the security context. This contains the
    // authentication method references we want to include in the authorization request
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    // Checking to see if this filter has been applied already (if so, this attribute will have
    // already been set)
    Object amrAttribute = request.getAttribute(AUTHORIZATION_REQUEST_INCLUDES_AMR);

    if (amrAttribute == null && auth instanceof ExtendedAuthenticationToken) {
      Set<IamAuthenticationMethodReference> amrSet =
          ((ExtendedAuthenticationToken) auth).getAuthenticationMethodReferences();
      String amrClaim = parseAuthenticationMethodReferences(amrSet);

      ExtendedHttpServletRequest extendedRequest =
          new ExtendedHttpServletRequest((HttpServletRequest) request, amrClaim);

      extendedRequest.setAttribute(AUTHORIZATION_REQUEST_INCLUDES_AMR, Boolean.TRUE);
      request = extendedRequest;
    }

    chain.doFilter(request, response);
  }

  /**
   * Convert a set of authentication method references into a request parameter string Values are
   * separated with a + symbol
   * 
   * @param amrSet the set of authentication method references
   * @return the parsed string
   */
  private String parseAuthenticationMethodReferences(Set<IamAuthenticationMethodReference> amrSet) {
    String amrClaim = "";
    Iterator<IamAuthenticationMethodReference> it = amrSet.iterator();
    while (it.hasNext()) {
      IamAuthenticationMethodReference current = it.next();
      amrClaim += current.getName() + "+";
    }

    // Remove trailing + symbol at end of string
    amrClaim = amrClaim.substring(0, amrClaim.length() - 1);
    return amrClaim;
  }
}
