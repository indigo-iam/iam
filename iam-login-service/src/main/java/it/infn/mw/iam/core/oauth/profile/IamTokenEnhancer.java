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
import java.util.Date;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.OIDCTokenService;
import org.mitre.openid.connect.service.UserInfoService;
import org.mitre.openid.connect.token.ConnectTokenEnhancer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.core.oauth.scope.pdp.IamScopeFilter;

@SuppressWarnings("deprecation")
public class IamTokenEnhancer extends ConnectTokenEnhancer {

  @Autowired
  private UserInfoService userInfoService;

  @Autowired
  private OIDCTokenService connectTokenService;

  @Autowired
  private IamScopeFilter scopeFilter;

  @Autowired
  private JWTProfileResolver profileResolver;

  @Autowired
  private Clock clock;

  private SignedJWT signClaims(JWTClaimsSet claims) {
    JWSAlgorithm signingAlg = getJwtService().getDefaultSigningAlgorithm();

    JWSHeader header = new JWSHeader(signingAlg, null, null, null, null, null, null, null, null,
        null, getJwtService().getDefaultSignerKeyId(), null, null);
    SignedJWT signedJWT = new SignedJWT(header, claims);

    getJwtService().signJwt(signedJWT);
    return signedJWT;

  }

  @Override
  public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
      OAuth2Authentication authentication) {

    OAuth2Request originalAuthRequest = authentication.getOAuth2Request();

    String username = authentication.getName();
    String clientId = originalAuthRequest.getClientId();

    UserInfo userInfo = userInfoService.getByUsernameAndClientId(username, clientId);

    scopeFilter.filterScopes(accessToken.getScope(), authentication);

    Instant tokenIssueInstant = clock.instant();

    OAuth2AccessTokenEntity accessTokenEntity = (OAuth2AccessTokenEntity) accessToken;

    JWTProfile profile =
        profileResolver.resolveProfile(authentication.getOAuth2Request().getClientId());
    
    JWTClaimsSet atClaims = profile.getAccessTokenBuilder()
      .buildAccessToken(accessTokenEntity, authentication, userInfo, tokenIssueInstant);

    accessTokenEntity.setJwt(signClaims(atClaims));

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
        && !authentication.isClientOnly()) {

      ClientDetailsEntity client = getClientService().loadClientByClientId(clientId);

      JWT idToken = connectTokenService.createIdToken(client, originalAuthRequest,
          Date.from(tokenIssueInstant),
          userInfo.getSub(), accessTokenEntity);

      accessTokenEntity.setIdToken(idToken);
    }

    return accessTokenEntity;
  }

}
