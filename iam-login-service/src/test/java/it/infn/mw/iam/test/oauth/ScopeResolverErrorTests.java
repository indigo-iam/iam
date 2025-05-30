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

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Mockito.when;

import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

import it.infn.mw.iam.core.userinfo.DefaultOAuth2AuthenticationScopeResolver;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;

@SuppressWarnings("deprecation")
@RunWith(MockitoJUnitRunner.class)
public class ScopeResolverErrorTests {

  public static final String TOKEN_VALUE = "token-value";

  OAuth2Request oauthRequest = new MockOAuth2Request("test", new String[] {"openid", "profile"});

  @Mock
  OAuth2Authentication auth;

  @Mock
  OAuth2AuthenticationDetails authDetails;

  @Mock
  OAuth2Request authRequest;

  @InjectMocks
  DefaultOAuth2AuthenticationScopeResolver scopeResolver;

  @Before
  public void setup() {
    when(auth.getOAuth2Request()).thenReturn(oauthRequest);
  }

  @Test
  public void testNullDetailsHandled() {
    Set<String> scopes = scopeResolver.resolveScope(auth);
    assertThat(scopes, hasSize(2));
    assertThat(scopes, hasItem("openid"));
    assertThat(scopes, hasItem("profile"));
  }

  @Test
  public void testNullTokenValueHandled() {
    when(auth.getDetails()).thenReturn(authDetails);
    Set<String> scopes = scopeResolver.resolveScope(auth);
    assertThat(scopes, hasSize(2));
    assertThat(scopes, hasItem("openid"));
    assertThat(scopes, hasItem("profile"));
  }
}
