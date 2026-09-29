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
package it.infn.mw.iam.config.security.filters;

import static it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder.CERT_HASH_FIELD_NAME;
import static it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder.CLIENT_CERT_HEADER;
import static it.infn.mw.iam.core.oauth.profile.common.BaseExtraClaimNames.CNF;
import static it.infn.mw.iam.util.x509.X509Utils.getCertificateThumbprint;

import java.io.IOException;
import java.text.ParseException;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class MtlsTokenBindingFilter extends OncePerRequestFilter {

  private static final String AUTH_HEADER = "Authorization";

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws ServletException, IOException {

    try {
      validateTokenBinding(request);
    } catch (ParseException e) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid access token format");
      return;
    } catch (InsufficientAuthenticationException e) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
      return;
    }

    chain.doFilter(request, response);
  }

  private void validateTokenBinding(HttpServletRequest request) throws ParseException {

    String authorization = request.getHeader(AUTH_HEADER);

    if (authorization == null || !authorization.startsWith("Bearer ")) {
      return;
    }

    String tokenValue = authorization.substring("Bearer ".length()).trim();
    JWTClaimsSet claims = SignedJWT.parse(tokenValue).getJWTClaimsSet();
    Map<String, Object> cnf = claims.getJSONObjectClaim(CNF);

    if (cnf == null || !cnf.containsKey(CERT_HASH_FIELD_NAME)) {
      return;
    }

    Object expectedThumbprint = cnf.get(CERT_HASH_FIELD_NAME);

    if (expectedThumbprint == null) {
      throw new InsufficientAuthenticationException("Missing mTLS certificate thumbprint claim");
    }

    String certificate = request.getHeader(CLIENT_CERT_HEADER);

    if (certificate == null || certificate.isBlank()) {
      throw new InsufficientAuthenticationException("Missing mTLS certificate");
    }

    String presentedThumbprint = getCertificateThumbprint(certificate).orElseThrow(
        () -> new InsufficientAuthenticationException("Missing mTLS certificate thumbprint"));

    if (!expectedThumbprint.toString().equals(presentedThumbprint)) {
      throw new InsufficientAuthenticationException("mTLS certificate thumbprint mismatch");
    }
  }
}
