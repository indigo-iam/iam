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

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.service.OIDCTokenService;
import org.mitre.openid.connect.token.ConnectTokenEnhancer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public class IamTokenEnhancer extends ConnectTokenEnhancer {

  public static final String EXPIRES_IN_KEY = "expires_in";

  public static final String INVALID_PARAMETER = "Value of 'expires_in' parameter is not valid";

  private IamAccountService accountService;
  private ClientService clientService;
  private OIDCTokenService connectTokenService;
  private JWTProfileResolver profileResolver;
  private Clock clock;

  public IamTokenEnhancer(Clock clock, IamAccountService accountService, ClientService clientService,
      OIDCTokenService connectTokenService, JWTProfileResolver profileResolver) {

    this.clock = clock;
    this.accountService = accountService;
    this.clientService = clientService;
    this.connectTokenService = connectTokenService;
    this.profileResolver = profileResolver;
  }

  private SignedJWT signClaims(JWTClaimsSet claims) {
    JWSAlgorithm signingAlg = getJwtService().getDefaultSigningAlgorithm();

    JWSHeader header = new JWSHeader(signingAlg, null, null, null, null, null, null, null, null,
        null, getJwtService().getDefaultSignerKeyId(), null, null);
    SignedJWT signedJWT = new SignedJWT(header, claims);

    getJwtService().signJwt(signedJWT);
    return signedJWT;

  }

  private Date ensureValidExpiration(Map<String, String> requestParameters,
      OAuth2AccessTokenEntity token, Instant tokenIssueInstant) {
    try {
      Integer expiresIn = Integer.valueOf(requestParameters.get(EXPIRES_IN_KEY));
      Integer validExp = token.getClient().getAccessTokenValiditySeconds();
      if (expiresIn >= 0) {
        validExp = Math.min(expiresIn, token.getClient().getAccessTokenValiditySeconds());
      }
      return Date.from(tokenIssueInstant.plus(validExp, ChronoUnit.SECONDS));
    } catch (NumberFormatException e) {
      throw new InvalidRequestException(INVALID_PARAMETER);
    }
  }

  private Date computeExpTime(OAuth2Authentication authentication, OAuth2AccessTokenEntity token,
      Instant tokenIssueInstant) {

    OAuth2Request originalRequest = authentication.getOAuth2Request();
    if (originalRequest.isRefresh()) {
      TokenRequest refreshRequest = originalRequest.getRefreshTokenRequest();
      if (refreshRequest.getRequestParameters().containsKey(EXPIRES_IN_KEY)) {
        return ensureValidExpiration(refreshRequest.getRequestParameters(), token,
            tokenIssueInstant);
      }
      // don't use custom value from original request
      return Date.from(tokenIssueInstant.plus(token.getClient().getAccessTokenValiditySeconds(),
          ChronoUnit.SECONDS));
    }
    if (originalRequest.getRequestParameters().containsKey(EXPIRES_IN_KEY)) {
      return ensureValidExpiration(originalRequest.getRequestParameters(), token,
          tokenIssueInstant);
    }
    return token.getExpiration();
  }

  @Override
  public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
      OAuth2Authentication authentication) {

    OAuth2AccessTokenEntity accessTokenEntity = (OAuth2AccessTokenEntity) accessToken;

    OAuth2Request originalAuthRequest = authentication.getOAuth2Request();

    String clientId = originalAuthRequest.getClientId();

    ClientDetailsEntity client = clientService.findClientByClientId(clientId)
        .orElseThrow(() -> OAuth2Exception.create(OAuth2Exception.INVALID_CLIENT,
            "Invalid client id " + clientId));

    Instant tokenIssueInstant = clock.instant();

    JWTProfile profile = profileResolver.resolveProfile(client.getScope());

    accessTokenEntity
      .setExpiration(computeExpTime(authentication, accessTokenEntity, tokenIssueInstant));

    Optional<IamAccount> account = Optional.empty();
    if (!authentication.isClientOnly()) {
      String username = authentication.getName();
      account = accountService.findByUsername(username);
    }

    JWTClaimsSet atClaims = profile.getAccessTokenBuilder()
      .buildAccessToken(accessTokenEntity, authentication, account, tokenIssueInstant);

    accessTokenEntity.setJwt(signClaims(atClaims));
    accessTokenEntity.hashMe();

    /**
     * Authorization request scope MUST include "openid" in OIDC, but access token request may or
     * may not include the scope parameter. As long as the AuthorizationRequest has the proper
     * scope, we can consider this a valid OpenID Connect request. Otherwise, we consider it to be a
     * vanilla OAuth2 request.
     * 
     * Also, there must be a user authentication involved in the request for it to be considered
     * OIDC and not OAuth, so we check for that as well.
     */
    if (originalAuthRequest.getScope().contains(SystemScopeService.OPENID_SCOPE)
        && account.isPresent()) {

      JWT idToken = connectTokenService.createIdToken(client, originalAuthRequest,
          Date.from(tokenIssueInstant), account.get().getUuid(), accessTokenEntity);

      accessTokenEntity.setIdToken(idToken);
    }

    return accessTokenEntity;
  }

}
