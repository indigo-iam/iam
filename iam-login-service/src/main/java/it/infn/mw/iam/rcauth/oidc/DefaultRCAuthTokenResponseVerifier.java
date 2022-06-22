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
package it.infn.mw.iam.rcauth.oidc;

import static java.util.Objects.isNull;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.rcauth.RCAuthError;
import it.infn.mw.iam.rcauth.RCAuthProperties;
import it.infn.mw.iam.rcauth.RCAuthTokenResponse;

@Component
@ConditionalOnProperty(name="rcauth.enabled", havingValue="true")
public class DefaultRCAuthTokenResponseVerifier implements RCAuthTokenResponseVerifier {

  final JWKSetCacheService jwkService;
  final RCAuthProperties rcAuthProperties;
  final IamProperties iamProperties;
  final Clock clock;

  @Autowired
  public DefaultRCAuthTokenResponseVerifier(Clock clock, JWKSetCacheService jwkService,
      RCAuthProperties rcAuthProperties, IamProperties iamProperties) {
    this.clock = clock;
    this.jwkService = jwkService;
    this.rcAuthProperties = rcAuthProperties;
    this.iamProperties = iamProperties;
  }

  protected void checkIssuer(JWTClaimsSet idTokenClaims) {
    String issuer = idTokenClaims.getIssuer();
    if (isNull(issuer)) {
      throw new RCAuthError("Required claim not found in token: iss");
    }
  }

  protected void checkTemporalValidity(JWTClaimsSet idTokenClaims) {

    Instant now = clock.instant();
    Instant expirationTime = idTokenClaims.getExpirationTime().toInstant();

    if (now.isAfter(expirationTime)) {
      throw new RCAuthError("invalid token: token has expired on " + expirationTime);
    }
  }

  protected void validateTokenSignature(ServerConfiguration serverConfiguration,
      SignedJWT idToken) {

    JWTSigningAndValidationService validator =
        jwkService.getValidator(serverConfiguration.getJwksUri());

    if (isNull(validator)) {
      throw new RCAuthError(
          "Could not resolve JSON Web Keys for provider: " + serverConfiguration.getIssuer());
    }

    if (!validator.validateSignature(idToken)) {
      throw new RCAuthError("Invalid token signature");
    }
  }


  @Override
  public void verify(ServerConfiguration serverConfiguration, RCAuthTokenResponse tokenResponse) {

    String idTokenString = tokenResponse.getIdToken();

    try {

      SignedJWT idTokenJwt = SignedJWT.parse(idTokenString);
      JWTClaimsSet idTokenClaims = idTokenJwt.getJWTClaimsSet();

      checkIssuer(idTokenClaims);
      checkTemporalValidity(idTokenClaims);
      validateTokenSignature(serverConfiguration, idTokenJwt);

    } catch (ParseException e) {
      throw new RCAuthError("Token parse error: " + e.getMessage(), e);
    }

  }
}
