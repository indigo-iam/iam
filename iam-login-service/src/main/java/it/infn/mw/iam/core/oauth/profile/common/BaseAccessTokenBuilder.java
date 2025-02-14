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
import static it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter.TOKEN_EXCHANGE_GRANT_TYPE;
import static java.util.Objects.isNull;

import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
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

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.JWTAccessTokenBuilder;

@SuppressWarnings("deprecation")
public abstract class BaseAccessTokenBuilder implements JWTAccessTokenBuilder {

  public static final Logger LOG = LoggerFactory.getLogger(BaseAccessTokenBuilder.class);

  public static final String AUDIENCE = "audience";
  protected static final List<String> AUD_KEYS = Arrays.asList("aud", AUDIENCE);
  public static final String RESOURCE = "resource";
  public static final String SCOPE_CLAIM_NAME = "scope";

  public static final String ACT_CLAIM_NAME = "act";
  public static final String CLIENT_ID_CLAIM_NAME = "client_id";
  public static final String SPACE = " ";

  public static final String SUBJECT_TOKEN = "subject_token";

  protected final IamProperties properties;

  protected final Splitter splitter = Splitter.on(' ').trimResults().omitEmptyStrings();

  public BaseAccessTokenBuilder(IamProperties properties) {
    this.properties = properties;
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

  protected boolean isRefreshTokenRequest(OAuth2Authentication authentication) {
    return !isNull(authentication.getOAuth2Request().getRefreshTokenRequest());
  }

  protected boolean hasRefreshTokenAudienceRequest(OAuth2Authentication authentication) {
    final String audience = authentication.getOAuth2Request()
      .getRefreshTokenRequest()
      .getRequestParameters()
      .get(AUDIENCE);

    return !isNullOrEmpty(audience);
  }

  protected boolean hasRefreshTokenResourceRequest(OAuth2Authentication authentication) {
    final String audience = authentication.getOAuth2Request()
      .getRefreshTokenRequest()
      .getRequestParameters()
      .get(RESOURCE);

    return !isNullOrEmpty(audience);
  }

  protected boolean hasAudienceRequest(OAuth2Authentication authentication) {

    final Set<String> audience = AUD_KEYS.stream()
      .filter(aud -> authentication.getOAuth2Request().getRequestParameters().containsKey(aud))
      .collect(Collectors.toSet());

    return !audience.isEmpty();
  }

  protected boolean hasResourceRequest(OAuth2Authentication authentication) {
    final String resource = authentication.getOAuth2Request().getRequestParameters().get(RESOURCE);
    return !isNullOrEmpty(resource);
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

    String audience = getAudience(authentication);

    if (!isNullOrEmpty(audience)) {
      builder.audience(splitter.splitToList(audience));
    }

    if (isTokenExchangeRequest(authentication)) {
      handleClientTokenExchange(builder, token, authentication, userInfo);
    }

    return builder;
  }

  private String getAudience(OAuth2Authentication authentication) {
    if (isRefreshTokenRequest(authentication)) {
      return getFirstNonEmpty(
          authentication.getOAuth2Request().getRefreshTokenRequest().getRequestParameters(),
          RESOURCE, AUDIENCE);
    }

    if (hasResourceRequest(authentication)) {
      return authentication.getOAuth2Request().getRequestParameters().get(RESOURCE);
    }

    return AUD_KEYS.stream()
      .map(key -> authentication.getOAuth2Request().getRequestParameters().get(key))
      .filter(value -> !isNullOrEmpty(value))
      .findFirst()
      .orElse(null);
  }

  private String getFirstNonEmpty(Map<String, String> params, String... keys) {
    return Arrays.stream(keys)
      .map(params::get)
      .filter(value -> !isNullOrEmpty(value))
      .findFirst()
      .orElse(null);
  }

}
