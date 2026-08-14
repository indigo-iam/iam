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
package it.infn.mw.iam.core.oauth.introspection;

import java.text.ParseException;
import java.time.Clock;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.audit.events.tokens.IntrospectionEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.exceptions.UnauthorizedClientException;
import it.infn.mw.iam.core.oauth.introspection.model.IntrospectionResponse;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@SuppressWarnings("deprecation")
@Service
public class IamIntrospectionService implements IntrospectionService {

  private static final Logger LOG = LoggerFactory.getLogger(IamIntrospectionService.class);

  private static final String SUSPENDED_CLIENT_ERROR =
      "Client %s has been suspended and is not allowed to call introspection endpoint";

  private final Clock clock;
  private final JWTProfileResolver profileResolver;
  private final ResourceServerTokenServices tokenService;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final ClientService clientService;
  private final ApplicationEventPublisher eventPublisher;
  private final IamProperties iamProperties;
  private final OpaqueTokenIntrospector introspector;

  public IamIntrospectionService(Clock clock, JWTProfileResolver profileResolver,
      ResourceServerTokenServices tokenService, IamOAuthRefreshTokenRepository refreshTokenRepo,
      ClientService clientService, ApplicationEventPublisher eventPublisher,
      IamProperties iamProperties, OpaqueTokenIntrospector introspector) {

    this.clock = clock;
    this.profileResolver = profileResolver;
    this.tokenService = tokenService;
    this.refreshTokenRepo = refreshTokenRepo;
    this.clientService = clientService;
    this.eventPublisher = eventPublisher;
    this.iamProperties = iamProperties;
    this.introspector = introspector;
  }

  @Override
  public IntrospectionResponse introspect(Authentication auth, String tokenValue,
      TokenTypeHint tokenTypeHint) {

    Objects.requireNonNull(tokenValue, "Unexpected null tokenValue");

    ClientDetailsEntity authenticatedClient = loadClient(auth);
    clientService.useClient(authenticatedClient);

    IntrospectionResponse response = null;
    TokenInfo info = null;
    try {

      info = getTokenInfo(tokenValue, tokenTypeHint);
      validateClient(authenticatedClient);

      switch (info.tokenType) {
        case REFRESH_TOKEN:
          OAuth2RefreshTokenEntity rt = refreshTokenRepo.findByTokenValue(tokenValue)
            .orElseThrow(() -> new InvalidTokenException("Invalid refresh token: token not found"));
          response = introspectRefreshToken(authenticatedClient, rt, info);
          break;
        case ACCESS_TOKEN:
        default:
          String issuer = info.claims.getIssuer();

          if (iamProperties.getIssuer().equals(issuer)) {
            OAuth2AccessTokenEntity at =
                (OAuth2AccessTokenEntity) tokenService.readAccessToken(tokenValue);
            response = introspectAccessToken(authenticatedClient, at, info);
          } else {
            OAuth2AuthenticatedPrincipal introspectionResult = introspector.introspect(tokenValue);

            LOG.info("Introspection result for token issued by {}: active={}", issuer,
                introspectionResult.getAttribute("active"));

            response = convertIntrospectionResponse(introspectionResult);
          }
          break;
      }

    } catch (UnauthorizedClientException e) {

      LOG.info("Failed introspection of token, client validation error: {}", e.getMessage());
      return IntrospectionResponse.inactive();

    } catch (InvalidTokenException | InvalidGrantException e) {

      LOG.info("Failed introspection of token, invalid token value: {}", e.getMessage());
      return IntrospectionResponse.inactive();

    } catch (ParseException e) {

      LOG.info("Failed introspection of token, malformed token: {}", e.getMessage());
      return IntrospectionResponse.inactive();

    } catch (RestClientException e) {

      LOG.info("Failed introspection of token, discovery failed: {}", e.getMessage());
      return IntrospectionResponse.inactive();
    }

    eventPublisher.publishEvent(new IntrospectionEvent(this, info.jti, info.tokenType, response));
    return response;
  }

  private TokenInfo getTokenInfo(String tokenValue, TokenTypeHint tokenTypeHint)
      throws ParseException {

    JWT jwt = JWTParser.parse(tokenValue);
    if (tokenTypeHint == null) {
      tokenTypeHint = getTokenType(jwt);
    }
    JWTClaimsSet claims = jwt.getJWTClaimsSet();
    return new TokenInfo(tokenValue, tokenTypeHint, claims, claims.getJWTID());
  }

  private TokenTypeHint getTokenType(JWT jwt) {

    if (jwt instanceof PlainJWT) {
      return TokenTypeHint.REFRESH_TOKEN;
    }
    if (jwt instanceof SignedJWT) {
      return TokenTypeHint.ACCESS_TOKEN;
    }
    throw new InvalidTokenException(
        "Token introspection error: expected a SignedJWT or PlainJWT object");
  }

  private void validateClient(ClientDetailsEntity c)
      throws UnauthorizedClientException, InvalidTokenException {

    if (!c.isActive()) {
      String errorMsg = String.format(SUSPENDED_CLIENT_ERROR, c.getClientId());
      LOG.error(errorMsg);
      throw new UnauthorizedClientException(errorMsg);
    }
  }

  private boolean isExpired(OAuth2AccessTokenEntity at) {

    if (at.getExpiration() == null) {
      return false;
    }
    return at.getExpiration().toInstant().isBefore(clock.instant());
  }

  private boolean isExpired(OAuth2RefreshTokenEntity rt) {

    if (rt.getExpiration() == null) {
      return false;
    }
    return rt.getExpiration().toInstant().isBefore(clock.instant());
  }

  private IntrospectionResponse introspectRefreshToken(ClientDetailsEntity authenticatedClient,
      OAuth2RefreshTokenEntity rt, TokenInfo info) throws InvalidTokenException {

    if (isExpired(rt) || notYetValid(info.claims)) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    JWTProfile profile = profileResolver.resolveProfile(rt.getClient().getScope(),
        rt.getAuthenticationHolder().getAuthentication().getOAuth2Request().getScope());
    profile.getIntrospectionResultHelper()
      .assembleIntrospectionResult(rt, authenticatedClient)
      .forEach(builder::addField);
    info.claims.getClaims().forEach(builder::addFieldIfAbsent);
    return builder.build();
  }

  private IntrospectionResponse introspectAccessToken(ClientDetailsEntity authenticatedClient,
      OAuth2AccessTokenEntity at, TokenInfo info) throws InvalidTokenException {

    if (isExpired(at) || notYetValid(info.claims)) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    JWTProfile profile = profileResolver.resolveProfile(at.getClient().getScope(), at.getScope());
    profile.getIntrospectionResultHelper()
      .assembleIntrospectionResult(at, authenticatedClient)
      .forEach(builder::addField);
    info.claims.getClaims().forEach(builder::addFieldIfAbsent);
    return builder.build();
  }

  private boolean notYetValid(JWTClaimsSet claims) {

    Optional<Date> notBefore = Optional.ofNullable(claims.getNotBeforeTime());
    return notBefore.isPresent() && notBefore.get().after(Date.from(clock.instant()));
  }

  private ClientDetailsEntity loadClient(Authentication auth) {

    return clientService
      .findClientByClientId(
          auth instanceof OAuth2Authentication oauth2 ? oauth2.getOAuth2Request().getClientId()
              : auth.getName())
      .orElseThrow();
  }

  public record TokenInfo(String tokenValue, TokenTypeHint tokenType, JWTClaimsSet claims,
      String jti) {
  }

  private IntrospectionResponse convertIntrospectionResponse(
      OAuth2AuthenticatedPrincipal principal) {
    IntrospectionResponse.Builder builder =
        new IntrospectionResponse.Builder(principal.getAttribute("active"));

    principal.getAttributes().forEach(builder::addField);

    return builder.build();
  }
}
