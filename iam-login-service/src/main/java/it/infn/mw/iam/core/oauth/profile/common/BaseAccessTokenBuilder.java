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
import static com.nimbusds.jwt.JWTClaimNames.AUDIENCE;
import static it.infn.mw.iam.core.oauth.IamOAuth2RequestFactory.AUD_KEY;
import static it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter.TOKEN_EXCHANGE_GRANT_TYPE;
import static it.infn.mw.iam.core.oauth.profile.common.BaseExtraClaimNames.ACR;
import static it.infn.mw.iam.core.oauth.profile.common.BaseExtraClaimNames.ACT;
import static java.util.Objects.isNull;
import static java.util.stream.Collectors.joining;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.google.common.collect.Maps;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.AccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@SuppressWarnings("deprecation")
public abstract class BaseAccessTokenBuilder implements AccessTokenBuilder {

  private static final Logger LOG = LoggerFactory.getLogger(BaseAccessTokenBuilder.class);

  protected static final String SPACE = " ";
  protected static final String SUBJECT_TOKEN = "subject_token";

  private final IamProperties properties;
  private final ScopeFilter scopeFilter;
  private final IamTotpMfaRepository totpMfaRepository;
  private final AccountUtils accountUtils;
  private final ClaimValueHelper claimValueHelper;
  private final ScopeClaimTranslationService scopeClaimTranslationService;

  protected BaseAccessTokenBuilder(IamProperties properties, IamTotpMfaRepository totpMfaRepository,
      AccountUtils accountUtils, ScopeFilter scopeFilter, ClaimValueHelper claimValueHelper,
      ScopeClaimTranslationService scopeClaimTranslationService) {
    this.properties = properties;
    this.totpMfaRepository = totpMfaRepository;
    this.accountUtils = accountUtils;
    this.scopeFilter = scopeFilter;
    this.claimValueHelper = claimValueHelper;
    this.scopeClaimTranslationService = scopeClaimTranslationService;
  }

  protected IamProperties getProperties() {
    return properties;
  }

  protected ScopeFilter getScopeFilter() {
    return scopeFilter;
  }

  protected IamTotpMfaRepository getTotpMfaRepository() {
    return totpMfaRepository;
  }

  protected AccountUtils getAccountUtils() {
    return accountUtils;
  }

  protected ClaimValueHelper getClaimValueHelper() {
    return claimValueHelper;
  }

  protected ScopeClaimTranslationService getScopeClaimTranslationService() {
    return scopeClaimTranslationService;
  }

  @Override
  public Set<String> getAdditionalAuthnInfoClaims() {
    return Set.of(StandardClaimNames.NAME, StandardClaimNames.EMAIL,
        StandardClaimNames.PREFERRED_USERNAME);
  }

  @Override
  public Set<String> getRequiredClaims() {
    return Set.of();
  }

  @Override
  public JWTClaimsSet buildAccessToken(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication, Optional<IamAccount> account, Instant issueTime) {

    Builder builder = new JWTClaimsSet.Builder();

    /* base claims */
    builder.subject(account.isPresent() ? account.get().getUuid() : authentication.getName());
    builder.issuer(getProperties().getIssuer());
    builder.issueTime(Date.from(issueTime));
    builder.expirationTime(token.getExpiration());
    builder.jwtID(UUID.randomUUID().toString());
    builder.claim(BaseExtraClaimNames.CLIENT_ID, token.getClient().getClientId());

    /* audience claim */
    addAudience(builder, authentication);

    /* token request management */
    if (isTokenExchangeRequest(authentication)) {
      handleClientTokenExchange(builder, authentication);
    }

    /* add ACR claim if present */
    if (authentication.getUserAuthentication() instanceof SavedUserAuthentication savedAuth
        && savedAuth.getAdditionalInfo().get(ACR) != null) {
      builder.claim(ACR, savedAuth.getAdditionalInfo().get(ACR));
    }

    /* update token scopes filtering the requested ones */
    Set<String> requestedScopes = getRequestedScopes(token, authentication);
    token.setScope(scopeFilter.filterScopes(requestedScopes, authentication));

    /* include scope claim if configured */
    if (isIncludeScope() && !token.getScope().isEmpty()) {
      builder.claim(BaseExtraClaimNames.SCOPE, token.getScope().stream().collect(joining(SPACE)));
    }

    /* include nbf claim if configured */
    if (isIncludeNbf()) {
      builder.notBeforeTime(Date.from(issueTime
        .minus(Duration.ofSeconds(getProperties().getAccessToken().getNbfOffsetSeconds()))));
    }

    /* include the additional authentication claims if configured */
    if (isIncludeAuthnInfo() && account.isPresent()) {
      includeAdditionalAuthnInfoClaims(builder, token, authentication, account.get());
    }

    /* include the required claims if set */
    includeRequiredClaims(builder, authentication, account);

    return builder.build();
  }

  private Set<String> getRequestedScopes(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication) {

    Set<String> requestedScopes = new HashSet<>();
    if (authentication.getOAuth2Request().isRefresh()
        && !authentication.getOAuth2Request().getRefreshTokenRequest().getScope().isEmpty()) {
      requestedScopes.addAll(authentication.getOAuth2Request().getRefreshTokenRequest().getScope());
    } else {
      requestedScopes.addAll(token.getAuthenticationHolder().getScope());
    }
    return requestedScopes;
  }

  private void includeRequiredClaims(Builder builder, OAuth2Authentication authentication,
      Optional<IamAccount> account) {

    getRequiredClaims().stream().flatMap(claim -> {
      Object value = getClaimValueHelper().resolveClaim(claim, authentication, account);
      if (getClaimValueHelper().isValidClaimValue(value)) {
        return Stream.of(Map.entry(claim, value));
      } else {
        return Stream.<Map.Entry<String, Object>>empty();
      }
    }).forEach(entry -> builder.claim(entry.getKey(), entry.getValue()));
  }

  protected void includeAdditionalAuthnInfoClaims(Builder builder, OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication, IamAccount iamAccount) {

    Set<String> requiredClaims =
        getScopeClaimTranslationService().getClaimsForScopeSet(token.getScope());
    /* filter only the authentication claims that are required by the requested scopes */
    getAdditionalAuthnInfoClaims().stream().filter(requiredClaims::contains).flatMap(claim -> {
      Object value =
          getClaimValueHelper().resolveClaim(claim, authentication, Optional.of(iamAccount));
      if (getClaimValueHelper().isValidClaimValue(value)) {
        return Stream.of(Map.entry(claim, value));
      } else {
        return Stream.<Map.Entry<String, Object>>empty();
      }
    }).forEach(entry -> builder.claim(entry.getKey(), entry.getValue()));
  }

  protected boolean isIncludeScope() {

    return getProperties().getAccessToken().isIncludeScope();
  }

  protected boolean isIncludeNbf() {

    return getProperties().getAccessToken().isIncludeNbf();
  }

  protected boolean isIncludeAuthnInfo() {

    return getProperties().getAccessToken().isIncludeAuthnInfo();
  }


  protected boolean hasAudience(OAuth2Authentication authentication) {

    return hasAudienceRequest(authentication) || hasRefreshTokenAudienceRequest(authentication);
  }

  protected void addAudience(Builder builder, OAuth2Authentication authentication) {

    String audience = "";

    if (hasAudienceRequest(authentication)) {
      audience = authentication.getOAuth2Request().getRequestParameters().get(AUDIENCE);
    }
    if (hasRefreshTokenAudienceRequest(authentication)) {
      audience = authentication.getOAuth2Request()
        .getRefreshTokenRequest()
        .getRequestParameters()
        .get(AUDIENCE);
    }

    if (audience != null && !audience.trim().isEmpty()) {
      List<String> auds = Arrays.asList(audience.trim().split("\\s+"));
      if (auds.size() == 1) {
        builder.claim(JWTClaimNames.AUDIENCE, auds.get(0));
      } else {
        builder.audience(auds);
      }
    }
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
      OAuth2Authentication authentication) {

    try {
      JWT subjectToken = resolveSubjectTokenFromRequest(authentication.getOAuth2Request());

      if (authentication.isClientOnly()) {
        builder.subject(subjectToken.getJWTClaimsSet().getSubject());
      }

      Map<String, Object> actClaimContent = Maps.newHashMap();
      actClaimContent.put(JWTClaimNames.SUBJECT, authentication.getOAuth2Request().getClientId());

      Object subjectTokenActClaim = subjectToken.getJWTClaimsSet().getClaim(ACT);

      if (!isNull(subjectTokenActClaim)) {
        actClaimContent.put(ACT, subjectTokenActClaim);
      }

      builder.claim(ACT, actClaimContent);

    } catch (ParseException e) {
      LOG.error("Error getting claims from subject token: {}", e.getMessage(), e);
    }
  }

  protected boolean hasRefreshTokenAudienceRequest(OAuth2Authentication authentication) {
    if (!isNull(authentication.getOAuth2Request().getRefreshTokenRequest())) {
      final String audience = authentication.getOAuth2Request()
        .getRefreshTokenRequest()
        .getRequestParameters()
        .get(AUDIENCE);
      return !isNullOrEmpty(audience);
    }
    return false;
  }

  protected boolean hasAudienceRequest(OAuth2Authentication authentication) {
    final String audience = authentication.getOAuth2Request().getRequestParameters().get(AUD_KEY);
    return !isNullOrEmpty(audience);
  }

  protected boolean isValidClaimValue(Object value) {

    if (value instanceof Collection<?> coll) {
      return !coll.isEmpty();
    }
    return value != null;
  }
}
