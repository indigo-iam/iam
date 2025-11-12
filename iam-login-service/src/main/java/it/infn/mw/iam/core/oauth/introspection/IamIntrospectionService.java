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
import java.util.Date;
import java.util.Objects;
import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.audit.events.tokens.IntrospectionEvent;
import it.infn.mw.iam.core.oauth.exceptions.UnauthorizedClientException;
import it.infn.mw.iam.core.oauth.introspection.model.IntrospectionResponse;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;

@SuppressWarnings("deprecation")
@Service
public class IamIntrospectionService
    implements IntrospectionService {

  private static final Logger LOG = LoggerFactory.getLogger(IamIntrospectionService.class);

  private static final String NOT_ALLOWED_CLIENT_ERROR =
      "Client %s is not allowed to call introspection endpoint";
  private static final String SUSPENDED_CLIENT_ERROR =
      "Client %s has been suspended and is not allowed to call introspection endpoint";

  private final JWTProfileResolver profileResolver;
  private final OAuth2TokenEntityService tokenService;
  private final ClientService clientService;
  private final ApplicationEventPublisher eventPublisher;

  public IamIntrospectionService(JWTProfileResolver profileResolver,
      OAuth2TokenEntityService tokenService, ClientService clientService,
      ApplicationEventPublisher eventPublisher) {

    this.profileResolver = profileResolver;
    this.tokenService = tokenService;
    this.clientService = clientService;
    this.eventPublisher = eventPublisher;
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
          OAuth2RefreshTokenEntity rt = tokenService.getRefreshToken(tokenValue);
          response = introspectRefreshToken(authenticatedClient, rt, info);
          break;
        case ACCESS_TOKEN:
        default:
          OAuth2AccessTokenEntity at = tokenService.readAccessToken(tokenValue);
          response = introspectAccessToken(authenticatedClient, at, info);
          break;
      }

    } catch (UnauthorizedClientException e) {

      LOG.info("Failed introspection of token, client validation error: {}", e.getMessage());
      return IntrospectionResponse.inactive();

    } catch (InvalidTokenException e) {

      LOG.info("Failed introspection of token, invalid token value: {}", e.getMessage());
      return IntrospectionResponse.inactive();

    } catch (ParseException e) {

      LOG.info("Failed introspection of token, malformed token: {}", e.getMessage());
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

    // check if client has been suspended
    if (!c.isActive()) {
      String errorMsg = String.format(SUSPENDED_CLIENT_ERROR, c.getClientId());
      LOG.error(errorMsg);
      throw new UnauthorizedClientException(errorMsg);
    }

    // check if client is allowed to introspect tokens
    if (!c.isAllowIntrospection()) {
      String errorMsg = String.format(NOT_ALLOWED_CLIENT_ERROR, c.getClientId());
      LOG.error(errorMsg);
      throw new UnauthorizedClientException(errorMsg);
    }
  }

  private IntrospectionResponse introspectRefreshToken(ClientDetailsEntity authenticatedClient,
      OAuth2RefreshTokenEntity rt, TokenInfo info) throws InvalidTokenException {

    if (rt.isExpired() || notYetValid(info.claims)) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    JWTProfile profile = profileResolver.resolveProfile(rt.getClient().getScope());
    profile.getIntrospectionResultHelper()
      .assembleIntrospectionResult(rt, authenticatedClient)
      .forEach(builder::addField);
    // add all the others avoiding duplicates/override
    info.claims.getClaims().forEach(builder::addFieldIfAbsent);
    return builder.build();
  }

  private IntrospectionResponse introspectAccessToken(ClientDetailsEntity authenticatedClient,
      OAuth2AccessTokenEntity at, TokenInfo info) throws InvalidTokenException {

    if (at.isExpired() || notYetValid(info.claims)) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    JWTProfile profile = profileResolver.resolveProfile(at.getClient().getScope());
    profile.getIntrospectionResultHelper()
      .assembleIntrospectionResult(at, authenticatedClient)
      .forEach(builder::addField);
    // add all the others avoiding duplicates/override
    info.claims.getClaims().forEach(builder::addFieldIfAbsent);
    return builder.build();
  }

  private boolean notYetValid(JWTClaimsSet claims) {

    Optional<Date> notBefore = Optional.ofNullable(claims.getNotBeforeTime());
    return notBefore.isPresent() && notBefore.get().after(new Date());
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
}
