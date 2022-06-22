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

import static java.lang.String.format;
import static java.util.Objects.isNull;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.assertion.JWTBearerAssertionAuthenticationToken;
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
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.config.IamProperties;

public class IAMJWTBearerAuthenticationProvider implements AuthenticationProvider {

  public static final Logger LOG =
      LoggerFactory.getLogger(IAMJWTBearerAuthenticationProvider.class);

  private static final GrantedAuthority ROLE_CLIENT = new SimpleGrantedAuthority("ROLE_CLIENT");

  private static final int CLOCK_SKEW_IN_SECONDS = 300;

  private static final String INVALID_SIGNATURE_ALGO = "Invalid signature algorithm: %s";

  private final Clock clock;
  private final ClientDetailsEntityService clientService;
  private final ClientKeyCacheService validators;

  private final String tokenEndpoint;

  public IAMJWTBearerAuthenticationProvider(Clock clock, IamProperties iamProperties,
      ClientDetailsEntityService clientService, ClientKeyCacheService validators) {

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
        || client.getTokenEndpointAuthMethod().equals(AuthMethod.NONE)
        || client.getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_BASIC)
        || client.getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_POST)) {

      throw new AuthenticationServiceException(
          "Client does not support JWT-based client autentication");
    }

    JWSAlgorithm alg = jws.getHeader().getAlgorithm();

    if (client.getTokenEndpointAuthSigningAlg() != null
        && !client.getTokenEndpointAuthSigningAlg().equals(alg)) {
      invalidBearerAssertion(invalidSignatureAlgorithm(alg));
    }

    if (client.getTokenEndpointAuthMethod().equals(AuthMethod.PRIVATE_KEY)) {
      if (!JWSAlgorithm.Family.SIGNATURE.contains(alg)) {
        invalidBearerAssertion(invalidSignatureAlgorithm(alg));
      }
    } else if (client.getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_JWT)
        && !JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {
      invalidBearerAssertion(invalidSignatureAlgorithm(alg));
    }
  }

  private void signatureChecks(ClientDetailsEntity client, SignedJWT jws) {
    JWSAlgorithm alg = jws.getHeader().getAlgorithm();

    JWTSigningAndValidationService validator =
        Optional.ofNullable(validators.getValidator(client, alg))
          .orElseThrow(() -> new AuthenticationServiceException(
              format("Unable to resolve validator for client '%s' and algorithm '%s'",
                  client.getClientId(), alg.getName())));

    if (!validator.validateSignature(jws)) {
      invalidBearerAssertion("invalid signature");
    }
  }

  private void invalidBearerAssertion(String msg) {
    throw new AuthenticationServiceException(
        String.format("invalid jwt bearer assertion: %s", msg));
  }

  private void assertionChecks(ClientDetailsEntity client, SignedJWT jws) throws ParseException {

    JWTClaimsSet jwtClaims = jws.getJWTClaimsSet();

    if (isNull(jwtClaims.getIssuer())) {
      invalidBearerAssertion("issuer is null");
    } else if (!jwtClaims.getIssuer().equals(client.getClientId())) {
      invalidBearerAssertion("issuer does not match client id");
    }

    if (isNull(jwtClaims.getExpirationTime())) {
      invalidBearerAssertion("expiration time not set");
    }

    Instant nowSkewed = clock.instant().minusSeconds(CLOCK_SKEW_IN_SECONDS);

    if (Date.from(nowSkewed).after(jwtClaims.getExpirationTime())) {
      invalidBearerAssertion("expired assertion token");
    }

    if (!isNull(jwtClaims.getNotBeforeTime())) {

      nowSkewed = clock.instant().plusSeconds(CLOCK_SKEW_IN_SECONDS);
      if (Date.from(nowSkewed).before(jwtClaims.getNotBeforeTime())) {
        invalidBearerAssertion("assertion is not yet valid");
      }
    }

    if (!isNull(jwtClaims.getIssueTime())) {
      nowSkewed = clock.instant().plusSeconds(CLOCK_SKEW_IN_SECONDS);
      if (Date.from(nowSkewed).before(jwtClaims.getIssueTime())) {
        invalidBearerAssertion("assertion was issued in the future");
      }
    }

    if (isNull(jwtClaims.getAudience())) {
      invalidBearerAssertion("assertion audience is null");
    } else {
      if (!jwtClaims.getAudience().contains(tokenEndpoint)) {
        invalidBearerAssertion("invalid audience");
      }
    }

    if (isNull(jwtClaims.getJWTID())) {
      invalidBearerAssertion("jti is null");
      // no further jti validation is implemented currently
    }
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    JWTBearerAssertionAuthenticationToken jwtAuth =
        (JWTBearerAssertionAuthenticationToken) authentication;

    ClientDetailsEntity client = clientService.loadClientByClientId(jwtAuth.getName());

    if (isNull(client)) {
      throw new UsernameNotFoundException("Unknown client: " + jwtAuth.getName());
    }

    try {


      final JWT jwt = jwtAuth.getJwt();

      if (isNull(jwt)) {
        invalidBearerAssertion("Null JWT in authentication token");
      }

      if (!(jwt instanceof SignedJWT)) {
        invalidBearerAssertion("Unsupported JWT type: " + jwt.getClass().getName());
      }

      SignedJWT jws = (SignedJWT) jwt;

      clientAuthMethodChecks(client, jws);

      signatureChecks(client, jws);

      assertionChecks(client, jws);

      Set<GrantedAuthority> authorities = new HashSet<>(client.getAuthorities());
      authorities.add(ROLE_CLIENT);

      return new JWTBearerAssertionAuthenticationToken(jwt, authorities);

    } catch (ParseException e) {
      throw new AuthenticationServiceException("JWT parse error:" + e.getMessage(), e);
    }
  }


  @Override
  public boolean supports(Class<?> authentication) {
    return JWTBearerAssertionAuthenticationToken.class.isAssignableFrom(authentication);
  }

}
