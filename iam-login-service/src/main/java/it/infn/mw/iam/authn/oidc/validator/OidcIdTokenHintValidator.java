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
package it.infn.mw.iam.authn.oidc.validator;

import java.text.ParseException;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.core.jwk.JWTSigningAndValidationService;

@Component
public class OidcIdTokenHintValidator {

  private final JWTSigningAndValidationService jwtService;
  private final String issuer;

  public OidcIdTokenHintValidator(JWTSigningAndValidationService jwtService,
      @Value("${iam.issuer}") String issuer) {
    this.jwtService = jwtService;
    this.issuer = issuer;
  }

  public boolean isValid(SignedJWT idToken) {
    if (!jwtService.validateSignature(idToken)) {
      return false;
    }

    try {
      JWTClaimsSet claims = idToken.getJWTClaimsSet();

      String tokenIssuer = claims.getIssuer();

      if (tokenIssuer == null || tokenIssuer.isBlank()) {
        return false;
      }

      if (!issuer.equals(tokenIssuer)) {
        return false;
      }

      List<String> audience = claims.getAudience();
      if (audience == null || audience.isEmpty()) {
        return false;
      }

      return true;

    } catch (ParseException e) {
      return false;
    }
  }
}
