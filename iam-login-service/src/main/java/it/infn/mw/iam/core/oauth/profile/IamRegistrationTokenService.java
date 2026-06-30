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
package it.infn.mw.iam.core.oauth.profile;

import static it.infn.mw.iam.core.oauth.profile.common.BaseExtraClaimNames.CLIENT_ID;
import static it.infn.mw.iam.core.oauth.profile.common.BaseExtraClaimNames.SCOPE;

import java.time.Clock;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.SystemScopeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.audit.events.client.ClientRegistrationAccessTokenRotatedEvent;
import it.infn.mw.iam.audit.events.tokens.RegistrationTokenIssuedEvent;
import it.infn.mw.iam.audit.events.tokens.ResourceTokenIssuedEvent;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;

@SuppressWarnings("deprecation")
@Service
@Transactional
public class IamRegistrationTokenService implements RegistrationTokenService {

  public static final Logger LOG = LoggerFactory.getLogger(IamRegistrationTokenService.class);

  private final Clock clock;
  private final IamProperties properties;
  private final JWTSigningAndValidationService jwtService;
  private final IamOAuthAccessTokenRepository tokenRepo;
  private final IamAuthenticationHolderRepository authHolderRepo;
  private final TokenRevocationService revocationService;
  private final ApplicationEventPublisher eventPublisher;

  public IamRegistrationTokenService(Clock clock, IamProperties properties,
      JWTSigningAndValidationService jwtService, IamOAuthAccessTokenRepository tokenRepo,
      IamAuthenticationHolderRepository authHolderRepo, TokenRevocationService revocationService,
      ApplicationEventPublisher eventPublisher) {
    this.clock = clock;
    this.properties = properties;
    this.jwtService = jwtService;
    this.tokenRepo = tokenRepo;
    this.authHolderRepo = authHolderRepo;
    this.revocationService = revocationService;
    this.eventPublisher = eventPublisher;
  }

  @Override
  public OAuth2AccessTokenEntity createRegistrationAccessToken(ClientDetailsEntity client) {

    OAuth2AccessTokenEntity registrationToken = saveRegistrationToken(
        buildRegistrationAccessToken(client, SystemScopeService.REGISTRATION_TOKEN_SCOPE));
    eventPublisher.publishEvent(new RegistrationTokenIssuedEvent(this, registrationToken));
    return registrationToken;
  }

  @Override
  public OAuth2AccessTokenEntity createResourceAccessToken(ClientDetailsEntity client) {

    OAuth2AccessTokenEntity resourceToken = saveRegistrationToken(
        buildRegistrationAccessToken(client, SystemScopeService.RESOURCE_TOKEN_SCOPE));
    eventPublisher.publishEvent(new ResourceTokenIssuedEvent(this, resourceToken));
    return resourceToken;
  }

  @Override
  public OAuth2AccessTokenEntity rotateRegistrationAccessTokenForClient(
      ClientDetailsEntity client) {

    Optional<OAuth2AccessTokenEntity> currentToken =
        tokenRepo.findRegistrationToken(client.getId());
    OAuth2AccessTokenEntity rotatedToken = createRegistrationAccessToken(client);
    eventPublisher.publishEvent(new ClientRegistrationAccessTokenRotatedEvent(this, client));
    currentToken.ifPresent(revocationService::revokeRegistrationToken);
    return rotatedToken;
  }

  private OAuth2AccessTokenEntity buildRegistrationAccessToken(ClientDetailsEntity client,
      String scope) {

    Map<String, String> authorizationParameters = new HashMap<>();
    OAuth2Request clientAuth = new OAuth2Request(authorizationParameters, client.getClientId(),
        Set.of(Authorities.ROLE_CLIENT), true, Set.of(scope), null, null, null, null);

    OAuth2Authentication authentication = new OAuth2Authentication(clientAuth, null);

    OAuth2AccessTokenEntity token = new OAuth2AccessTokenEntity();
    token.setClient(client);
    token.setScope(Set.of(scope));

    AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
    authHolder.setAuthentication(authentication);
    token.setAuthenticationHolder(authHolder);
    token.setExpiration(null); // infinite token

    JWTClaimsSet claims = new JWTClaimsSet.Builder().audience(List.of(client.getClientId()))
      .issuer(properties.getIssuer())
      .issueTime(Date.from(clock.instant()))
      .jwtID(UUID.randomUUID().toString())
      .claim(CLIENT_ID, client.getClientId())
      .claim(SCOPE, scope)
      .build();

    JWSAlgorithm signingAlg = jwtService.getDefaultSigningAlgorithm();
    JWSHeader header =
        new JWSHeader.Builder(signingAlg).keyID(jwtService.getDefaultSignerKeyId()).build();
    SignedJWT signed = new SignedJWT(header, claims);

    jwtService.signJwt(signed);

    token.setJwt(signed);
    token.hashMe();

    return token;
  }

  private OAuth2AccessTokenEntity saveRegistrationToken(OAuth2AccessTokenEntity token) {

    AuthenticationHolderEntity authHolder = authHolderRepo.save(token.getAuthenticationHolder());
    token.setAuthenticationHolder(authHolder);
    return tokenRepo.save(token);
  }
}
