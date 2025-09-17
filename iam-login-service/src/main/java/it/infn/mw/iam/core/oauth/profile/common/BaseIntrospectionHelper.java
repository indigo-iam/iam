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
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2AccessTokenEntity accessToken,
      ClientDetailsEntity authenticatedClient) throws ParseException {

    ClientDetailsEntity client = accessToken.getClient();
    JWTClaimsSet claims = accessToken.getJwt().getJWTClaimsSet();
    Map<String, Object> result = assembleCommonClaims(claims, client, TokenTypeHint.ACCESS_TOKEN);
    result.put(SUB, claims.getSubject());
    result.put(IAT, claims.getIssueTime());
    result.put(ISS, claims.getIssuer());
    includeIfNotNull(result, SCOPE, accessToken.getScope().stream().collect(joining(" ")));
    return result;
  }

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2RefreshTokenEntity refreshToken,
      ClientDetailsEntity authenticatedClient) throws ParseException {

    ClientDetailsEntity client = refreshToken.getClient();
    JWTClaimsSet claims = refreshToken.getJwt().getJWTClaimsSet();
    Map<String, Object> result = assembleCommonClaims(claims, client, TokenTypeHint.REFRESH_TOKEN);
    includeIfNotEmpty(result, SCOPE, refreshToken.getAuthenticationHolder().getScope());
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
    includeIfNotNull(result, EXP, claims.getExpirationTime());
    result.put(JTI, claims.getJWTID());
    Optional<IamAccount> account = loadUserFrom(claims.getSubject());
    if (account.isPresent()) {
      result.put(USERNAME, account.get().getUsername());
    }
    includeIfNotNull(result, NBF, claims.getNotBeforeTime());
    includeIfNotEmpty(result, AUD, claims.getAudience());
    return result;
  }

  protected void includeIfNotNull(Map<String, Object> result, String key, Object value) {

    if (value != null) {
      result.put(key, String.valueOf(value));
    }
  }

  protected void includeIfNotEmpty(Map<String, Object> result, String key, Collection<?> value) {

    if (!value.isEmpty()) {
      result.put(key, value.stream().map(String::valueOf).collect(joining(" ")));
    }
  }

}
