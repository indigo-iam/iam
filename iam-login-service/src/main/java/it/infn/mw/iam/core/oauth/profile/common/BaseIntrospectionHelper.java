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
package it.infn.mw.iam.core.oauth.profile.common;

import static java.util.Objects.nonNull;
import static java.util.stream.Collectors.joining;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.AUD;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.EXP;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.IAT;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.ISS;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.JTI;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.NBF;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.SCOPE;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.SUB;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.TOKEN_TYPE;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.USERNAME;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;

import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.core.oauth.profile.IntrospectionResultHelper;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;

public abstract class BaseIntrospectionHelper implements IntrospectionResultHelper {

  public static final Logger LOG = LoggerFactory.getLogger(BaseIntrospectionHelper.class);

  private final IamAccountService accountService;

  protected BaseIntrospectionHelper(IamAccountService accountService) {

    this.accountService = accountService;
  }

  protected IamAccountService getAccountService() {

    return accountService;
  }

  protected JWTClaimsSet getClaimsSet(JWT jwt) {
    try {
      return jwt.getJWTClaimsSet();
    } catch (ParseException e) {
      throw new IllegalStateException("Unexpected error: " + e.getMessage());
    }
  }

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2AccessTokenEntity accessToken,
      ClientDetailsEntity authenticatedClient) {

    ClientDetailsEntity client = accessToken.getClient();
    JWTClaimsSet claims = getClaimsSet(accessToken.getJwt());
    Map<String, Object> result = assembleCommonClaims(claims, client, TokenTypeHint.ACCESS_TOKEN);
    result.put(SUB, claims.getSubject());
    result.put(IAT, claims.getIssueTime().getTime() / 1000);
    result.put(ISS, claims.getIssuer());
    if (nonNull(accessToken.getScope())) {
      result.put(SCOPE, accessToken.getScope().stream().map(String::valueOf).collect(joining(" ")));
    }
    return result;
  }

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2RefreshTokenEntity refreshToken,
      ClientDetailsEntity authenticatedClient) {

    ClientDetailsEntity client = refreshToken.getClient();
    JWTClaimsSet claims = getClaimsSet(refreshToken.getJwt());
    Map<String, Object> result = assembleCommonClaims(claims, client, TokenTypeHint.REFRESH_TOKEN);
    if (nonNull(refreshToken.getAuthenticationHolder().getScope())) {
      result.put(SCOPE,
          refreshToken.getAuthenticationHolder()
            .getScope()
            .stream()
            .map(String::valueOf)
            .collect(joining(" ")));
    }
    return result;
  }

  protected Optional<IamAccount> loadUserFrom(String subject) {
    return accountService.findByUuid(subject);
  }

  protected Map<String, Object> assembleCommonClaims(JWTClaimsSet claims,
      ClientDetailsEntity client, TokenTypeHint tokenType) {

    Map<String, Object> result = new HashMap<>();
    result.put(TOKEN_TYPE, tokenType);
    result.put(CLIENT_ID, client.getClientId());
    if (nonNull(claims.getExpirationTime())) {
      result.put(EXP, claims.getExpirationTime().getTime() / 1000);
    }
    result.put(JTI, claims.getJWTID());
    Optional<IamAccount> account = loadUserFrom(claims.getSubject());
    if (account.isPresent()) {
      result.put(USERNAME, account.get().getUsername());
    }
    if (nonNull(claims.getNotBeforeTime())) {
      result.put(NBF, claims.getNotBeforeTime().getTime() / 1000);
    }
    /*
     * For OAuth 2.0 Token Introspection (RFC 7662), the AUD claim follows the same rules as in JWT
     * (RFC 7519, section 4.1.3) so it can be either a string (single audience), or an array of
     * strings (multiple audiences).
     */
    if (nonNull(claims.getAudience()) && !claims.getAudience().isEmpty()) {
      if (claims.getAudience().size() == 1) {
        result.put(AUD, claims.getAudience().get(0));
      } else {
        result.put(AUD, claims.getAudience());
      }
    }
    return result;
  }
}
