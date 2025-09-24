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
import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.audit.events.tokens.IntrospectionEvent;
import it.infn.mw.iam.core.oauth.exceptions.UnauthorizedClientException;
import it.infn.mw.iam.core.oauth.introspection.model.IntrospectionResponse;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;

@SuppressWarnings("deprecation")
@Service
public class IamIntrospectionService implements IntrospectionService, ApplicationEventPublisherAware {

  private static final Logger LOG = LoggerFactory.getLogger(IamIntrospectionService.class);

  private static final String NOT_ALLOWED_CLIENT_ERROR =
      "Client %s is not allowed to call introspection endpoint";
  private static final String SUSPENDED_CLIENT_ERROR =
      "Client %s has been suspended and is not allowed to call introspection endpoint";

  private final JWTProfileResolver profileResolver;
  private final OAuth2TokenEntityService tokenService;
  private final ClientDetailsEntityService clientService;
  private final TokenRevocationService revocationService;
  private ApplicationEventPublisher eventPublisher;

  public IamIntrospectionService(JWTProfileResolver profileResolver,
      OAuth2TokenEntityService tokenService, ClientDetailsEntityService clientService,
      TokenRevocationService revocationService) {

    this.profileResolver = profileResolver;
    this.tokenService = tokenService;
    this.clientService = clientService;
    this.revocationService = revocationService;
  }

  @Override
  public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.eventPublisher = applicationEventPublisher;
  }

  @Override
  public IntrospectionResponse introspect(Authentication auth, String tokenValue,
      TokenTypeHint tokenTypeHint) {

    IntrospectionResponse response = null;
    ClientDetailsEntity authenticatedClient = loadClient(auth);

    try {
      validate(authenticatedClient, tokenValue);
      JWT jwt = JWTParser.parse(tokenValue);

      if (jwt instanceof PlainJWT plainJwt) {
        // It's a RefreshToken
        OAuth2RefreshTokenEntity rt = tokenService.getRefreshToken(plainJwt.serialize());
        response = introspectRefreshToken(authenticatedClient, rt);
      } else if (jwt instanceof SignedJWT) {
        // It's an AccessToken
        OAuth2AccessTokenEntity at = tokenService.readAccessToken(tokenValue);
        response = introspectAccessToken(authenticatedClient, at);
      } else {
        LOG.warn("Token introspection error: expected a SignedJWT or PlainJWT object");
        response = IntrospectionResponse.inactive();
      }

    } catch (UnauthorizedClientException | InvalidTokenException | ParseException e) {

      LOG.warn("Token introspection error: {}", e.getMessage());
      response = IntrospectionResponse.inactive();
    }

    eventPublisher.publishEvent(new IntrospectionEvent(this, tokenValue, tokenTypeHint, response));
    return response;
  }

  private void validate(ClientDetailsEntity c, String tokenValue)
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

    // invalid null token to introspect
    if (Strings.isNullOrEmpty(tokenValue)) {
      String errorMsg = "Verify failed; token value is null";
      LOG.error(errorMsg);
      throw new InvalidTokenException(errorMsg);
    }
  }

  private IntrospectionResponse introspectRefreshToken(ClientDetailsEntity authenticatedClient,
      OAuth2RefreshTokenEntity rt) throws ParseException, InvalidTokenException {

    if (rt.isExpired() || isRevoked(rt) || notYetValid(rt.getJwt())) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    JWTProfile profile = profileResolver.resolveProfile(rt.getClient().getScope());
    profile.getIntrospectionResultHelper()
      .assembleIntrospectionResult(rt, authenticatedClient)
      .forEach(builder::addField);
    // add all the others avoiding duplicates/override
    rt.getJwt().getJWTClaimsSet().getClaims().forEach(builder::addFieldIfAbsent);
    return builder.build();
  }

  private IntrospectionResponse introspectAccessToken(ClientDetailsEntity authenticatedClient,
      OAuth2AccessTokenEntity at) throws InvalidTokenException, ParseException {

    if (at.isExpired() || isRevoked(at) || notYetValid(at.getJwt())) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    JWTProfile profile = profileResolver.resolveProfile(at.getClient().getScope());
    profile.getIntrospectionResultHelper()
      .assembleIntrospectionResult(at, authenticatedClient)
      .forEach(builder::addField);
    // add all the others avoiding duplicates/override
    at.getJwt().getJWTClaimsSet().getClaims().forEach(builder::addFieldIfAbsent);
    return builder.build();
  }

  private boolean notYetValid(JWT jwt) throws ParseException {

    Optional<Date> notBefore = Optional.ofNullable(jwt.getJWTClaimsSet().getNotBeforeTime());
    return notBefore.isPresent() && notBefore.get().after(new Date());
  }

  private boolean isRevoked(OAuth2AccessTokenEntity at)
      throws InvalidTokenException, ParseException {

    return revocationService.isAccessTokenRevoked((SignedJWT) at.getJwt());
  }

  private boolean isRevoked(OAuth2RefreshTokenEntity rt)
      throws InvalidTokenException, ParseException {

    return revocationService.isRefreshTokenRevoked((PlainJWT) rt.getJwt());
  }

  private ClientDetailsEntity loadClient(Authentication auth) {

    return clientService.loadClientByClientId(
        auth instanceof OAuth2Authentication oauth2 ? oauth2.getOAuth2Request().getClientId()
            : auth.getName());
  }
}
