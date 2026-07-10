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
package it.infn.mw.iam.authn.util;

import static java.util.Collections.emptyMap;

import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;

import com.google.common.collect.Maps;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

public class JwtUtils {

  public static final Logger LOG = LoggerFactory.getLogger(JwtUtils.class);

  public static final Set<JWSAlgorithm> UNSUPPORTED_IDTOKEN_SIGNATURE_ALGS =
      Set.of(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512);

  private JwtUtils() {
    // empty on purpose
  }

  public static Map<String, String> getClaimsAsMap(JWT jwt) {

    Map<String, String> claimsMap = Maps.newHashMap();

    JWTClaimsSet claims;

    try {
      claims = jwt.getJWTClaimsSet();
    } catch (ParseException e) {
      LOG.warn("Error parsing jwt claims: {}", e.getMessage(), e);
      return emptyMap();
    }

    for (String claimName : claims.getClaims().keySet()) {
      Object claimValue = claims.getClaim(claimName);

      if (claimValue instanceof String) {
        claimsMap.put(claimName, (String) claimValue);
      } else if (claimValue instanceof Number) {
        claimsMap.put(claimName, String.valueOf(claimValue));
      } else if (claimValue instanceof URI) {
        claimsMap.put(claimName, ((URI) claimValue).toString());
      } else if (claimValue instanceof URL) {
        claimsMap.put(claimName, ((URL) claimValue).toString());
      } else {
        LOG.warn("Unsupported claim type '{}' for claim '{}'... skipping it",
            claimValue.getClass().getName(), claimName);
      }
    }
    return claimsMap;
  }

  public static JWTClaimsSet parseClaims(JWT idToken) {

    try {
      return idToken.getJWTClaimsSet();
    } catch (ParseException e) {
      throw new AuthenticationServiceException(
          String.format("Error parsing JWT claims: %s", e.getMessage()));
    }
  }

  public static JWT parseToken(String tokenValue) {

    try {
      return JWTParser.parse(tokenValue);
    } catch (ParseException e) {
      throw new AuthenticationServiceException("Token parse error");
    }
  }

  public static JsonObject jsonStringSanityChecks(String jsonString) {

    JsonElement json = JsonParser.parseString(jsonString);
    if (!json.isJsonObject()) {
      throw new AuthenticationServiceException(
          String.format("Not a JSON object: %s", json.toString()));
    }
    return json.getAsJsonObject();
  }

  public static void validateSignature(JWT idToken, String clientAlg,
      JWTSigningAndValidationService jwtValidator) {

    Algorithm tokenAlg = idToken.getHeader().getAlgorithm();

    if (clientAlg != null && !clientAlg.equals(tokenAlg.toString())) {
      throw new AuthenticationServiceException(String
        .format("Token algorithm %s does not match expected algorithm %s", tokenAlg, clientAlg));
    }

    if (idToken instanceof PlainJWT) {

      if (clientAlg == null) {
        throw new AuthenticationServiceException(
            "Unsigned ID tokens can only be used if explicitly configured in client.");
      }

      if (tokenAlg != null && !tokenAlg.equals(Algorithm.NONE)) {
        throw new AuthenticationServiceException(
            "Unsigned token received, expected signature with " + tokenAlg);
      }
      return;
    }

    if (idToken instanceof SignedJWT signedIdToken) {

      if (UNSUPPORTED_IDTOKEN_SIGNATURE_ALGS.contains(tokenAlg)) {
        throw new UnsupportedOperationException(
            String.format("Symmetric ID token signing agorithm %s is not supported", tokenAlg));
      }

      if (jwtValidator == null) {
        throw new AuthenticationServiceException(
            "Unable to find an appropriate signature validator for ID token");
      }

      if (!jwtValidator.validateSignature(signedIdToken)) {
        throw new AuthenticationServiceException("ID token signature validation failed");
      }

      return;
    }

    throw new AuthenticationServiceException("Unexpected encrypted ID token");
  }

  public static void validateClaims(JWTClaimsSet idClaims, String expectedIssuer, String clientId,
      Date skewedMin, Date skewedMax) {

    String tokenIssuer = idClaims.getIssuer();
    if (tokenIssuer == null) {
      throw new AuthenticationServiceException("Issuer claim not present in the ID token");
    }

    if (!tokenIssuer.equals(expectedIssuer)) {
      throw new AuthenticationServiceException(String.format(
          "ID token issuer claim does not match the client configuration, expected %s got %s",
          expectedIssuer, tokenIssuer));
    }

    Date expiration = idClaims.getExpirationTime();
    if (expiration == null) {
      throw new AuthenticationServiceException("ID token does not have required expiration claim");
    }

    if (skewedMin.after(expiration)) {
      throw new AuthenticationServiceException(
          String.format("ID token is expired: %s", expiration));
    }

    Date notBefore = idClaims.getNotBeforeTime();
    if (notBefore != null && skewedMax.before(notBefore)) {
      throw new AuthenticationServiceException(
          String.format("ID token not valid until: %s", notBefore));
    }

    Date issuedAt = idClaims.getIssueTime();
    if (issuedAt == null) {
      throw new AuthenticationServiceException("ID token does not have required issued-at claim");
    }

    if (skewedMax.before(issuedAt)) {
      throw new AuthenticationServiceException(
          String.format("ID token was issued in the future: %s", issuedAt));
    }

    List<String> aud = idClaims.getAudience();
    if (aud.isEmpty()) {
      throw new AuthenticationServiceException("Audience claim not present in the ID token");
    }

    if (!aud.contains(clientId)) {
      throw new AuthenticationServiceException(
          String.format("ID token audience claim does not match the client configuration %s got %s",
              clientId, aud));
    }
  }

}
