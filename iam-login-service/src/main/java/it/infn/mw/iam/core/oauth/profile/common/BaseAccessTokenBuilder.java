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

import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.core.oauth.IamOAuth2RequestFactory.AUD_KEY;
import static it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter.TOKEN_EXCHANGE_GRANT_TYPE;
import static java.util.Objects.isNull;
import static java.util.stream.Collectors.joining;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.mitre.openid.connect.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.google.common.base.Splitter;
import com.google.common.collect.Maps;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.JWTAccessTokenBuilder;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;

@SuppressWarnings("deprecation")
public abstract class BaseAccessTokenBuilder implements JWTAccessTokenBuilder {

  public static final Logger LOG = LoggerFactory.getLogger(BaseAccessTokenBuilder.class);

  public static final String SCOPE_CLAIM_NAME = "scope";
  public static final String ACT_CLAIM_NAME = "act";
  public static final String CLIENT_ID_CLAIM_NAME = "client_id";
  public static final String SPACE = " ";

  public static final String SUBJECT_TOKEN = "subject_token";

  protected final IamProperties properties;
  protected final ScopeFilter scopeFilter;

  protected final Splitter splitter = Splitter.on(' ').trimResults().omitEmptyStrings();

  protected final IamTotpMfaRepository totpMfaRepository;

  protected final AccountUtils accountUtils;

  protected BaseAccessTokenBuilder(IamProperties properties, IamTotpMfaRepository totpMfaRepository,
      AccountUtils accountUtils, ScopeFilter scopeFilter) {
    this.properties = properties;
    this.totpMfaRepository = totpMfaRepository;
    this.accountUtils = accountUtils;
    this.scopeFilter = scopeFilter;
  }


  protected boolean isTokenExchangeRequest(OAuth2Authentication authentication) {
    return TOKEN_EXCHANGE_GRANT_TYPE.equals(authentication.getOAuth2Request().getGrantType());
  }

  protected JWT resolveSubjectTokenFromRequest(OAuth2Request request) {
    String subjectTokenString = request.getRequestParameters().get(SUBJECT_TOKEN);

    if (isNull(subjectTokenString)) {
      throw new InvalidRequestException("subject_token not found in token exchange request!");
    }

    try {
      return JWTParser.parse(subjectTokenString);
    } catch (ParseException e) {
      throw new InvalidRequestException("Error parsing subject token: " + e.getMessage(), e);
    }
  }


  protected void handleClientTokenExchange(JWTClaimsSet.Builder builder,
      OAuth2AccessTokenEntity token, OAuth2Authentication authentication, UserInfo userInfo) {

    try {
      JWT subjectToken = resolveSubjectTokenFromRequest(authentication.getOAuth2Request());

      if (authentication.isClientOnly()) {
        builder.subject(subjectToken.getJWTClaimsSet().getSubject());
      }

      Map<String, Object> actClaimContent = Maps.newHashMap();
      actClaimContent.put("sub", authentication.getOAuth2Request().getClientId());

      Object subjectTokenActClaim = subjectToken.getJWTClaimsSet().getClaim(ACT_CLAIM_NAME);

      if (!isNull(subjectTokenActClaim)) {
        actClaimContent.put("act", subjectTokenActClaim);
      }

      builder.claim(ACT_CLAIM_NAME, actClaimContent);

    } catch (ParseException e) {
      LOG.error("Error getting claims from subject token: {}", e.getMessage(), e);
    }
  }

  protected boolean hasRefreshTokenAudienceRequest(OAuth2Authentication authentication) {
    if (!isNull(authentication.getOAuth2Request().getRefreshTokenRequest())) {
      final String audience = authentication.getOAuth2Request()
        .getRefreshTokenRequest()
        .getRequestParameters()
        .get(AUD_KEY);
      return !isNullOrEmpty(audience);
    }
    return false;
  }

  protected boolean hasAudienceRequest(OAuth2Authentication authentication) {
    final String audience = authentication.getOAuth2Request().getRequestParameters().get(AUD_KEY);
    return !isNullOrEmpty(audience);
  }

  protected boolean hasScope(OAuth2Authentication authentication, String scope) {
    Set<String> scopes = authentication.getOAuth2Request().getScope();
    return scopes != null && scopes.contains(scope);
  }

  protected boolean hasEmailScope(OAuth2Authentication authentication) {
    return hasScope(authentication, "email");
  }

  protected boolean hasProfileScope(OAuth2Authentication authentication) {
    return hasScope(authentication, "profile");
  }

  protected JWTClaimsSet.Builder baseJWTSetup(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication, UserInfo userInfo, Instant issueTime) {

    String subject = null;

    if (userInfo == null) {
      subject = authentication.getName();
    } else {
      subject = userInfo.getSub();
    }

    Builder builder = new JWTClaimsSet.Builder().issuer(properties.getIssuer())
      .issueTime(Date.from(issueTime))
      .expirationTime(token.getExpiration())
      .subject(subject)
      .jwtID(UUID.randomUUID().toString());


    builder.claim(CLIENT_ID_CLAIM_NAME, token.getClient().getClientId());

    String audience = null;

    if (hasAudienceRequest(authentication)) {
      audience = authentication.getOAuth2Request().getRequestParameters().get(AUD_KEY);
    }

    if (hasRefreshTokenAudienceRequest(authentication)) {
      audience = authentication.getOAuth2Request()
        .getRefreshTokenRequest()
        .getRequestParameters()
        .get(AUD_KEY);
    }

    if (!isNullOrEmpty(audience)) {
      builder.audience(splitter.splitToList(audience));
    }

    addScopeClaim(builder, token);

    if (userInfo != null) {
      if (hasEmailScope(authentication)) {
        builder.claim("email", userInfo.getEmail());
        builder.claim("email_verified", userInfo.getEmailVerified());
      }

      if (hasProfileScope(authentication)) {
        builder.claim("name", userInfo.getName());
        builder.claim("given_name", userInfo.getGivenName());
        builder.claim("family_name", userInfo.getFamilyName());
        builder.claim("middle_name", userInfo.getMiddleName());
        builder.claim("nickname", userInfo.getNickname());
        builder.claim("picture", userInfo.getPicture());
        builder.claim("updated_at", userInfo.getUpdatedTime());
      }
    }

    if (isTokenExchangeRequest(authentication)) {
      handleClientTokenExchange(builder, token, authentication, userInfo);
    }

    addAcrClaimIfNeeded(builder, authentication);

    token.setScope(scopeFilter.filterScopes(token.getScope(), authentication));

    return builder;
  }

  protected void addAcrClaimIfNeeded(Builder builder, OAuth2Authentication authentication) {
    if (authentication.getUserAuthentication() instanceof SavedUserAuthentication savedAuth
        && savedAuth.getAdditionalInfo().get("acr") != null) {
      builder.claim("acr", savedAuth.getAdditionalInfo().get("acr"));
    }
  }

  protected void addScopeClaim(Builder builder, OAuth2AccessTokenEntity token) {
    if (!token.getScope().isEmpty()) {
      builder.claim(SCOPE_CLAIM_NAME, token.getScope().stream().collect(joining(SPACE)));
    }
  }
}
