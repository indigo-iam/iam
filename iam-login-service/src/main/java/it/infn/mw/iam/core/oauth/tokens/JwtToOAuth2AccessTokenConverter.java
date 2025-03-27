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
package it.infn.mw.iam.core.oauth.tokens;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.stereotype.Component;

import com.nimbusds.jwt.SignedJWT;

@SuppressWarnings("deprecation")
@Component
public class JwtToOAuth2AccessTokenConverter {

  private static final String EXP_CLAIM = "exp";
  private static final String REFRESH_TOKEN_CLAIM = "refresh_token";
  private static final String SCOPE_CLAIM = "scope";

  public OAuth2AccessToken convert(SignedJWT signedJWT) throws ParseException {

    // Extract claims
    Map<String, Object> claims = signedJWT.getJWTClaimsSet().getClaims();
    String tokenValue = signedJWT.serialize();
    Date expiration = signedJWT.getJWTClaimsSet().getExpirationTime();

    // Extract scopes (if present)
    Set<String> scope =
        claims.containsKey(SCOPE_CLAIM) ? Set.of(claims.get(SCOPE_CLAIM).toString().split(" "))
            : Set.of();

    // Create OAuth2AccessToken
    DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(tokenValue);
    accessToken.setExpiration(expiration);
    accessToken.setScope(scope);
    accessToken.setTokenType(OAuth2AccessToken.BEARER_TYPE);

    // Check if there's a refresh token claim
    if (claims.containsKey(REFRESH_TOKEN_CLAIM)) {
      String refreshTokenValue = claims.get(REFRESH_TOKEN_CLAIM).toString();
      OAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken(refreshTokenValue);
      accessToken.setRefreshToken(refreshToken);
    }

    // Additional information (optional)
    Map<String, Object> additionalInfo = new HashMap<>(claims);
    additionalInfo.remove(EXP_CLAIM);
    additionalInfo.remove(SCOPE_CLAIM);
    accessToken.setAdditionalInformation(additionalInfo);

    return accessToken;
  }
}
