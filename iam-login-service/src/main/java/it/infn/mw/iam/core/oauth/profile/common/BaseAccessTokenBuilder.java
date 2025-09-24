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
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.ACR;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.ACT;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.SCOPE;
import static java.util.Objects.isNull;
import static java.util.stream.Collectors.joining;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PREFERRED_USERNAME;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.google.common.base.Splitter;
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
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.persistence.repository.UserInfoAdapter;

@SuppressWarnings("deprecation")
public abstract class BaseAccessTokenBuilder implements AccessTokenBuilder {

  private static final Logger LOG = LoggerFactory.getLogger(BaseAccessTokenBuilder.class);

  protected static final String SPACE = " ";
  protected static final String SUBJECT_TOKEN = "subject_token";

  private final IamProperties properties;
  private final ScopeFilter scopeFilter;
  private final IamAccountRepository accountRepository;
  private final IamTotpMfaRepository totpMfaRepository;
  private final AccountUtils accountUtils;
  private final ClaimValueHelper claimValueHelper;
  private final ScopeClaimTranslationService scopeClaimTranslationService;
  private final Splitter splitter;

  protected BaseAccessTokenBuilder(IamProperties properties, IamAccountRepository accountRepository,
      IamTotpMfaRepository totpMfaRepository, AccountUtils accountUtils, ScopeFilter scopeFilter,
      ClaimValueHelper claimValueHelper,
      ScopeClaimTranslationService scopeClaimTranslationService) {
    this.properties = properties;
    this.accountRepository = accountRepository;
    this.totpMfaRepository = totpMfaRepository;
    this.accountUtils = accountUtils;
    this.scopeFilter = scopeFilter;
    this.claimValueHelper = claimValueHelper;
    this.scopeClaimTranslationService = scopeClaimTranslationService;
    this.splitter = Splitter.on(' ').trimResults().omitEmptyStrings();
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

  public ScopeClaimTranslationService getScopeClaimTranslationService() {
    return scopeClaimTranslationService;
  }

  protected Splitter getSplitter() {
    return splitter;
  }

  @Override
  public Set<String> getAdditionalAuthnInfoClaims() {
    return Set.of(NAME, EMAIL, PREFERRED_USERNAME);
  }

  @Override
  public JWTClaimsSet buildAccessToken(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication, UserInfo userInfo, Instant issueTime) {

    JWTClaimsSet.Builder builder = baseJWTSetup(token, authentication, userInfo, issueTime);

    IamAccount account =
        userInfo != null ? ((UserInfoAdapter) userInfo).getUserinfo().getIamAccount() : null;

    scopeClaimTranslationService.getClaimsForScopeSet(token.getScope()).forEach(c -> {
      Object value = this.getClaimValueHelper().resolveClaim(c, account, authentication);
      if (!Objects.isNull(value)) {
        if (value instanceof Collection<?> valueColl) {
          if (!valueColl.isEmpty()) {
            builder.claim(c, value);
          }
        } else {
          builder.claim(c, value);
        }
      }
    });
    return builder.build();
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

  private JWTClaimsSet.Builder baseJWTSetup(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication, UserInfo userInfo, Instant issueTime) {

    String subject = null;
    Object owner = null;

    if (userInfo == null) {
      subject = authentication.getName();
    } else {
      subject = userInfo.getSub();
      owner = accountRepository.findByUuid(subject)
        .orElseThrow(() -> new IllegalStateException(
            "Creating a token for a user which is not present on database!"));
    }

    Builder builder = new JWTClaimsSet.Builder().issuer(getProperties().getIssuer())
      .issueTime(Date.from(issueTime))
      .expirationTime(token.getExpiration())
      .subject(subject)
      .jwtID(UUID.randomUUID().toString());


    builder.claim(CLIENT_ID, token.getClient().getClientId());

    String audience = null;

    if (hasAudienceRequest(authentication)) {
      audience = authentication.getOAuth2Request().getRequestParameters().get(AUDIENCE);
    }

    if (hasRefreshTokenAudienceRequest(authentication)) {
      audience = authentication.getOAuth2Request()
        .getRefreshTokenRequest()
        .getRequestParameters()
        .get(AUDIENCE);
    }

    if (!isNullOrEmpty(audience)) {
      builder.audience(splitter.splitToList(audience));
    }

    if (isTokenExchangeRequest(authentication)) {
      handleClientTokenExchange(builder, token, authentication, userInfo);
    }

    addAcrClaimIfNeeded(builder, authentication);

    filterAndSetScopes(token, authentication);

    if (getProperties().getAccessToken().isIncludeScope() && !token.getScope().isEmpty()) {
      builder.claim(SCOPE, token.getScope().stream().collect(joining(SPACE)));
    }

    if (getProperties().getAccessToken().isIncludeAuthnInfo() && owner != null) {
      Set<String> requiredClaims =
          getScopeClaimTranslationService().getClaimsForScopeSet(token.getScope());
      requiredClaims.retainAll(getAdditionalAuthnInfoClaims());
      for (String claim : requiredClaims) {
        builder.claim(claim,
            getClaimValueHelper().resolveClaim(claim, (IamAccount) owner, authentication));
      }
    }

    if (getProperties().getAccessToken().isIncludeNbf()) {
      builder.notBeforeTime(Date.from(issueTime
        .minus(Duration.ofSeconds(getProperties().getAccessToken().getNbfOffsetSeconds()))));
    }

    return builder;
  }

  private void filterAndSetScopes(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication) {

    if (authentication.getOAuth2Request().isRefresh()
        && !authentication.getOAuth2Request().getRefreshTokenRequest().getScope().isEmpty()) {
      token.setScope(scopeFilter.filterScopes(
          authentication.getOAuth2Request().getRefreshTokenRequest().getScope(), authentication));
    } else {
      token.setScope(
          scopeFilter.filterScopes(token.getAuthenticationHolder().getScope(), authentication));
    }
  }

  protected void addAcrClaimIfNeeded(Builder builder, OAuth2Authentication authentication) {
    if (authentication.getUserAuthentication() instanceof SavedUserAuthentication savedAuth
        && savedAuth.getAdditionalInfo().get(ACR) != null) {
      builder.claim(ACR, savedAuth.getAdditionalInfo().get(ACR));
    }
  }
}
