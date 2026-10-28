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
package it.infn.mw.iam.test.oauth.profile;

import static it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter.TOKEN_EXCHANGE_GRANT_TYPE;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.google.common.collect.Maps;
import com.nimbusds.jwt.JWTClaimsSet;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamTokenEnhancerProperties.ExternalAuthnTokenInclusion;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.ScopeClaimTranslationService;
import it.infn.mw.iam.core.oauth.profile.common.BaseExtraClaimNames;
import it.infn.mw.iam.core.oauth.profile.iam.IamAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.SavedUserAuthentication;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class IamAccessTokenBuilderTests {

  IamProperties properties = new IamProperties();

  @Mock
  AccountUtils accountUtils;

  @Mock
  IamTotpMfaRepository totpMfaRepository;

  @Mock
  ScopeClaimTranslationService scService;

  @Mock
  ClaimValueHelper claimValueHelper;

  @Mock
  OAuth2AccessTokenEntity tokenEntity;

  @Mock
  ClientDetailsEntity client;

  @Mock
  OAuth2Authentication authentication;

  @Mock
  ScopeFilter scopeFilter;

  @Spy
  MockOAuth2Request oauth2Request =
      new MockOAuth2Request("clientId", new String[] {"openid", "profile"});

  @Mock
  IamAccount account;

  final Instant now = Clock.systemUTC().instant();

  IamAccessTokenBuilder tokenBuilder;

  @BeforeEach
  void setup() {
    RequestContextHolder
      .setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));

    tokenBuilder = new IamAccessTokenBuilder(properties, totpMfaRepository, accountUtils,
        scopeFilter, claimValueHelper, scService);

    when(tokenEntity.getExpiration()).thenReturn(null);
    when(tokenEntity.getClient()).thenReturn(client);
    when(client.getClientId()).thenReturn("client");
    when(authentication.getOAuth2Request()).thenReturn(oauth2Request);
    when(account.getUuid()).thenReturn("userinfo-sub");
    when(oauth2Request.getGrantType()).thenReturn(TOKEN_EXCHANGE_GRANT_TYPE);
  }

  @AfterEach
  void clearRequestContext() {
    RequestContextHolder.resetRequestAttributes();
  }

  @Test
  void testMissingSubjectTokenTokenExchangeErrors() {

    Optional<IamAccount> optAccount = Optional.ofNullable(account);
    InvalidRequestException thrown = assertThrows(InvalidRequestException.class,
        () -> tokenBuilder.buildAccessToken(tokenEntity, authentication, optAccount, now));
    assertThat(thrown.getMessage(), containsString("subject_token not found"));
  }

  @Test
  void testSubjectTokenNotParsable() {

    Optional<IamAccount> optAccount = Optional.ofNullable(account);
    Map<String, String> paramsMap = Maps.newHashMap();
    paramsMap.put("subject_token", "3427thjdfhgejt73ja");
    oauth2Request.setRequestParameters(paramsMap);
    InvalidRequestException thrown = assertThrows(InvalidRequestException.class,
        () -> tokenBuilder.buildAccessToken(tokenEntity, authentication, optAccount, now));
    assertThat(thrown.getMessage(), containsString("Error parsing subject token"));
  }

  @ParameterizedTest
  @CsvSource({"NEVER, false, false", "NEVER, true, false", "ACCESS_TOKENS, false, true",
      "ACCESS_TOKENS, true, true", "ID_TOKENS, false, false", "ID_TOKENS, true, false",
      "ALL, false, true", "ALL, true, true"})
  void externalAuthnInAccessTokenFollowsConfiguration(ExternalAuthnTokenInclusion inclusion,
      boolean includeAuthnInfo, boolean expectedForExternalAuthentication) {

    properties.getTokenEnhancer().setIncludeExternalAuthn(inclusion);
    properties.getAccessToken().setIncludeAuthnInfo(includeAuthnInfo);

    when(oauth2Request.getGrantType()).thenReturn("authorization_code");

    Set<String> scopes = Set.of("openid", "profile");
    AuthenticationHolderEntity holder = mock(AuthenticationHolderEntity.class);

    when(tokenEntity.getAuthenticationHolder()).thenReturn(holder);
    when(holder.getScope()).thenReturn(scopes);
    when(scopeFilter.filterScopes(eq(scopes), eq(authentication), anyString())).thenReturn(scopes);
    when(tokenEntity.getScope()).thenReturn(scopes);

    if (includeAuthnInfo) {
      // Keep unrelated profile claims out of this test.
      when(scService.getClaimsForScopeSet(scopes)).thenReturn(Set.of());
    }

    Map<String, String> authenticationTypes =
        Map.of(OidcExternalAuthenticationToken.class.getName(), "oidc",
            SamlExternalAuthenticationToken.class.getName(), "saml",
            UsernamePasswordAuthenticationToken.class.getName(), "local");

    for (Map.Entry<String, String> entry : authenticationTypes.entrySet()) {
      SavedUserAuthentication savedAuth = mock(SavedUserAuthentication.class);
      when(savedAuth.getAdditionalInfo()).thenReturn(Map.of());
      when(savedAuth.getSourceClass()).thenReturn(entry.getKey());
      when(authentication.getUserAuthentication()).thenReturn(savedAuth);

      boolean external = !"local".equals(entry.getValue());
      boolean expected = external && expectedForExternalAuthentication;

      Map<String, Object> externalAuthn = Map.of("type", entry.getValue());

      if (expected) {
        when(claimValueHelper.resolveClaim(BaseExtraClaimNames.EXTERNAL_AUTHN, authentication,
            Optional.of(account))).thenReturn(externalAuthn);
      }

      JWTClaimsSet result =
          tokenBuilder.buildAccessToken(tokenEntity, authentication, Optional.of(account), now);

      assertEquals(expected, result.getClaims().containsKey(IamExtraClaimNames.EXTERNAL_AUTHN),
          "Unexpected external_authn inclusion for " + entry.getValue());

      if (expected) {
        assertEquals(externalAuthn, result.getClaim(IamExtraClaimNames.EXTERNAL_AUTHN));
      }
    }

    if (!expectedForExternalAuthentication) {
      verify(claimValueHelper, never()).resolveClaim(eq(IamExtraClaimNames.EXTERNAL_AUTHN), any(),
          any());
    }
  }
}
