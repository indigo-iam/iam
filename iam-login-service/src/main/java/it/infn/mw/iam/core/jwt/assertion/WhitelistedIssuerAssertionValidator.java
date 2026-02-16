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
package it.infn.mw.iam.core.jwt.assertion;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.core.jwt.JwkSetCacheService;
import it.infn.mw.iam.core.jwt.JwtSigningAndValidationService;

public class WhitelistedIssuerAssertionValidator implements AssertionValidator {

  private static Logger logger = LoggerFactory.getLogger(WhitelistedIssuerAssertionValidator.class);

  private final JwkSetCacheService jwkCache;
  private Map<String, String> whitelist;

  public WhitelistedIssuerAssertionValidator(JwkSetCacheService jwkCache) {

    this.jwkCache = jwkCache;
    this.whitelist = new HashMap<>();
  }

  public Map<String, String> getWhitelist() {
    return whitelist;
  }

  public void setWhitelist(Map<String, String> whitelist) {
    this.whitelist = whitelist;
  }

  @Override
  public boolean isValid(JWT assertion) {

    if (!(assertion instanceof SignedJWT)) {
      return false;
    }

    JWTClaimsSet claims;
    try {
      claims = assertion.getJWTClaimsSet();
    } catch (ParseException e) {
      logger.debug("Invalid assertion claims");
      return false;
    }

    if (Strings.isNullOrEmpty(claims.getIssuer())) {
      logger.debug("No issuer for assertion, rejecting");
      return false;
    }

    if (!whitelist.containsKey(claims.getIssuer())) {
      logger.debug("Issuer is not in whitelist, rejecting");
      return false;
    }

    String jwksUri = whitelist.get(claims.getIssuer());

    JwtSigningAndValidationService validator = jwkCache.getValidator(jwksUri);

    return validator.validateSignature((SignedJWT) assertion);
  }

}
