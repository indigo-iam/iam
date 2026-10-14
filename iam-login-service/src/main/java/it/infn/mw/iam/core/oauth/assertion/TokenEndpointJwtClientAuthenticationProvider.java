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
package it.infn.mw.iam.core.oauth.assertion;

import static java.util.Objects.isNull;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.jwk.ClientKeyCacheService;
import it.infn.mw.iam.core.jwk.JWTSigningAndValidationService;
import it.infn.mw.iam.persistence.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

public class TokenEndpointJwtClientAuthenticationProvider implements AuthenticationProvider {

  public static final Logger LOG =
      LoggerFactory.getLogger(TokenEndpointJwtClientAuthenticationProvider.class);

  private static final GrantedAuthority ROLE_CLIENT = new SimpleGrantedAuthority("ROLE_CLIENT");

  private static final int CLOCK_SKEW_IN_SECONDS = 300;

  private static final String INVALID_SIGNATURE_ALGO = "Invalid signature algorithm: %s";

  private final Clock clock;
  private final ClientService clientService;
  private final ClientKeyCacheService validators;

  private final String tokenEndpoint;

  public TokenEndpointJwtClientAuthenticationProvider(Clock clock, IamProperties iamProperties,
      ClientService clientService, ClientKeyCacheService validators) {

    this.clock = clock;
    this.clientService = clientService;
    this.validators = validators;

    if (iamProperties.getIssuer().endsWith("/")) {
      tokenEndpoint = iamProperties.getIssuer() + "token";
    } else {
      tokenEndpoint = iamProperties.getIssuer() + "/token";
    }

  }

  private String invalidSignatureAlgorithm(JWSAlgorithm alg) {
    return String.format(INVALID_SIGNATURE_ALGO, alg.getName());
  }

  private void clientAuthMethodChecks(ClientDetailsEntity client, SignedJWT jws) {

    if (client.getTokenEndpointAuthMethod() == null
        || client.getTokenEndpointAuthMethod().equals(ClientAuthMethod.NONE)
        || client.getTokenEndpointAuthMethod().equals(ClientAuthMethod.SECRET_BASIC)
        || client.getTokenEndpointAuthMethod().equals(ClientAuthMethod.SECRET_POST)) {

      throw new AuthenticationServiceException(
          "Client does not support JWT-based client autentication");
    }

    JWSAlgorithm alg = jws.getHeader().getAlgorithm();

    if (client.getTokenEndpointAuthSigningAlg() != null
        && !client.getTokenEndpointAuthSigningAlg().equals(alg)) {
      throw invalidBearerAssertion(invalidSignatureAlgorithm(alg));
    }

    if (client.getTokenEndpointAuthMethod().equals(ClientAuthMethod.PRIVATE_KEY)) {
      if (!JWSAlgorithm.Family.SIGNATURE.contains(alg)) {
        throw invalidBearerAssertion(invalidSignatureAlgorithm(alg));
      }
    } else if (client.getTokenEndpointAuthMethod().equals(ClientAuthMethod.SECRET_JWT)) {
      throw new AuthenticationServiceException(ClientAuthMethod.SECRET_JWT + " has been deprecated");
    }
  }

  private void signatureChecks(ClientDetailsEntity client, SignedJWT jws) {
    JWSAlgorithm alg = jws.getHeader().getAlgorithm();

    JWTSigningAndValidationService validator =
        Optional.ofNullable(validators.getValidator(client, alg))
          .orElseThrow(() -> new AuthenticationServiceException(
              String.format("Unable to resolve validator for client '%s' and algorithm '%s'",
                  client.getClientId(), alg.getName())));

    if (!validator.validateSignature(jws)) {
      throw invalidBearerAssertion("invalid signature");
    }
  }

  private AuthenticationServiceException invalidBearerAssertion(String msg) {
    return new AuthenticationServiceException(
        String.format("invalid jwt bearer assertion: %s", msg));
  }

  private void assertionChecks(ClientDetailsEntity client, SignedJWT jws) throws ParseException {

    JWTClaimsSet jwtClaims = jws.getJWTClaimsSet();

    if (isNull(jwtClaims.getIssuer())) {
      throw invalidBearerAssertion("issuer is null");
    } else if (!jwtClaims.getIssuer().equals(client.getClientId())) {
      throw invalidBearerAssertion("issuer does not match client id");
    }

    if (isNull(jwtClaims.getExpirationTime())) {
      throw invalidBearerAssertion("expiration time not set");
    }

    Instant nowSkewed = clock.instant().minusSeconds(CLOCK_SKEW_IN_SECONDS);

    if (Date.from(nowSkewed).after(jwtClaims.getExpirationTime())) {
      throw invalidBearerAssertion("expired assertion token");
    }

    if (!isNull(jwtClaims.getNotBeforeTime())) {

      nowSkewed = clock.instant().plusSeconds(CLOCK_SKEW_IN_SECONDS);
      if (Date.from(nowSkewed).before(jwtClaims.getNotBeforeTime())) {
        throw invalidBearerAssertion("assertion is not yet valid");
      }
    }

    if (!isNull(jwtClaims.getIssueTime())) {
      nowSkewed = clock.instant().plusSeconds(CLOCK_SKEW_IN_SECONDS);
      if (Date.from(nowSkewed).before(jwtClaims.getIssueTime())) {
        throw invalidBearerAssertion("assertion was issued in the future");
      }
    }

    if (isNull(jwtClaims.getAudience())) {
      throw invalidBearerAssertion("assertion audience is null");
    } else {
      if (!jwtClaims.getAudience().contains(tokenEndpoint)) {
        throw invalidBearerAssertion("invalid audience");
      }
    }

    if (isNull(jwtClaims.getJWTID())) {
      throw invalidBearerAssertion("jti is null");
      // no further jti validation is implemented currently
    }
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    JwtAssertionAuthenticationToken jwtAuth = (JwtAssertionAuthenticationToken) authentication;

    ClientDetailsEntity client = clientService.findClientByClientId(jwtAuth.getName())
      .orElseThrow(() -> new UsernameNotFoundException("Client not found"));

    try {

      final SignedJWT jwt = jwtAuth.getCredentials();

      if (isNull(jwt)) {
        throw invalidBearerAssertion("Null JWT in authentication token");
      }

      clientAuthMethodChecks(client, jwt);

      signatureChecks(client, jwt);

      assertionChecks(client, jwt);

      Set<GrantedAuthority> authorities = new HashSet<>(client.getAuthorities());
      authorities.add(ROLE_CLIENT);

      return new JwtAssertionAuthenticationToken(jwt, authorities);

    } catch (ParseException e) {
      throw new AuthenticationServiceException("JWT parse error:" + e.getMessage(), e);
    }
  }


  @Override
  public boolean supports(Class<?> authentication) {
    return JwtAssertionAuthenticationToken.class.isAssignableFrom(authentication);
  }

}
