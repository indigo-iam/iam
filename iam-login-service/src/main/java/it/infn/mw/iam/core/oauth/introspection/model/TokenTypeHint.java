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
package it.infn.mw.iam.core.oauth.introspection.model;

import java.text.ParseException;

import org.mitre.oauth2.service.SystemScopeService;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.core.oauth.tokens.OAuthTokenClaims;

public enum TokenTypeHint {

  ACCESS_TOKEN, REFRESH_TOKEN, REGISTRATION_ACCESS_TOKEN, RESOURCE_ACCESS_TOKEN;

  public static TokenTypeHint valueFrom(JWT jwt) throws ParseException {

    if (jwt instanceof PlainJWT) {
      return TokenTypeHint.REFRESH_TOKEN;
    }
    if (jwt instanceof SignedJWT signedJwt) {
      String scopeClaim = signedJwt.getJWTClaimsSet().getStringClaim(OAuthTokenClaims.SCOPE_CLAIM);
      if (scopeClaim.equals(SystemScopeService.REGISTRATION_TOKEN_SCOPE)) {
        return TokenTypeHint.REGISTRATION_ACCESS_TOKEN;
      }
      if (scopeClaim.equals(SystemScopeService.RESOURCE_TOKEN_SCOPE)) {
        return TokenTypeHint.RESOURCE_ACCESS_TOKEN;
      }
      return TokenTypeHint.ACCESS_TOKEN;
    }

    throw new IllegalArgumentException("Expected a SignedJWT or PlainJWT object");
  }
}
