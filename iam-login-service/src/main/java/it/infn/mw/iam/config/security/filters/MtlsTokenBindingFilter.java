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
import java.util.Optional;

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
      /* check if access token contains certificate hash */
      String auth = request.getHeader(AUTH_HEADER);

      if (auth == null || !auth.startsWith("Bearer ")) {
        throw new InsufficientAuthenticationException("Missing or invalid Authorization header");
      }

      String tokenValue = auth.substring("Bearer ".length()).trim();

      try {
        SignedJWT jwt = SignedJWT.parse(tokenValue);
        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        Map<String, Object> cnf = claims.getJSONObjectClaim(CNF);

        if (cnf == null || !cnf.containsKey(CERT_HASH_FIELD_NAME)) {
          chain.doFilter(request, response);
        }

        String expectedThumbprint = cnf.get(CERT_HASH_FIELD_NAME).toString();

        /* check if certificate hashes match */
        String presentedCert = request.getHeader(CLIENT_CERT_HEADER);

        if (presentedCert == null || presentedCert.isBlank()) {
          throw new InsufficientAuthenticationException("Missing mTLS certificate");
        }

        Optional<String> presentedThumbprint = getCertificateThumbprint(presentedCert);

        if (presentedThumbprint.isEmpty()) {
          throw new InsufficientAuthenticationException("Missing mTLS certificate thumbprint");
        }

        if (!expectedThumbprint.equals(presentedThumbprint.get())) {
          throw new InsufficientAuthenticationException("mTLS certificate thumbprint mismatch");
        }

      } catch (ParseException e) {
        throw new InsufficientAuthenticationException("Invalid access token format");
      }

      chain.doFilter(request, response);
    } catch (InsufficientAuthenticationException e) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
    }
  }
}
