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
package it.infn.mw.iam.test.oauth;

import static it.infn.mw.iam.core.IamTokenService.sha256;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;

import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

import com.google.common.collect.Sets;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.core.userinfo.DefaultOAuth2AuthenticationScopeResolver;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
public class OAuth2AuthenticationScopeResolverTests {

  public static final String TOKEN_VALUE = "token-value";

  OAuth2Request oauthRequest = new MockOAuth2Request("test", new String[] {"openid", "profile"});

  @Mock
  OAuth2Authentication auth;

  @Mock
  OAuth2AccessTokenEntity tokenEntity;

  @Mock
  OAuth2AuthenticationDetails authDetails;

  @Mock
  IamOAuthAccessTokenRepository repo;

  @InjectMocks
  DefaultOAuth2AuthenticationScopeResolver scopeResolver;

  @BeforeEach
  void setup() {
    lenient().when(auth.getOAuth2Request()).thenReturn(oauthRequest);
  }

  @Test
  void testNullDetailsHandled() {
    Set<String> scopes = scopeResolver.resolveScope(auth);
    assertThat(scopes, hasSize(2));
    assertThat(scopes, hasItem("openid"));
    assertThat(scopes, hasItem("profile"));
  }

  @Test
  void testNullTokenValueHandled() {
    lenient().when(auth.getDetails()).thenReturn(authDetails);
    Set<String> scopes = scopeResolver.resolveScope(auth);
    assertThat(scopes, hasSize(2));
    assertThat(scopes, hasItem("openid"));
    assertThat(scopes, hasItem("profile"));
  }

  @Test
  void tokenNotFoundInRepoRaisesIllegalArgumentException() {
    lenient().when(auth.getDetails()).thenReturn(authDetails);
    lenient().when(authDetails.getTokenValue()).thenReturn(TOKEN_VALUE);
    assertThrows(IllegalArgumentException.class, () -> scopeResolver.resolveScope(auth));
  }

  @Test
  void tokenFound() {
    lenient().when(auth.getDetails()).thenReturn(authDetails);
    lenient().when(authDetails.getTokenValue()).thenReturn(TOKEN_VALUE);
    lenient().when(repo.findByTokenValue(sha256(TOKEN_VALUE)))
      .thenReturn(Optional.of(tokenEntity));
    lenient().when(tokenEntity.getScope()).thenReturn(Sets.newHashSet("openid"));
    Set<String> scopes = scopeResolver.resolveScope(auth);
    assertThat(scopes, hasSize(1));
    assertThat(scopes, hasItem("openid"));
  }
}
