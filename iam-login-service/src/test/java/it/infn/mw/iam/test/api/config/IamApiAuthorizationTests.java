/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2026
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
package it.infn.mw.iam.test.api.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.config.security.IamApiAuthorization;
import it.infn.mw.iam.core.userinfo.OAuth2AuthenticationScopeResolver;

@SuppressWarnings("deprecation")
class IamApiAuthorizationTests {

  private final OAuth2AuthenticationScopeResolver scopeResolver =
      mock(OAuth2AuthenticationScopeResolver.class);

  private final IamApiAuthorization authorization = new IamApiAuthorization(scopeResolver);

  @Test
  void deniesMissingAuthentication() {
    assertFalse(authorization.hasScope(null, "scim:write"));
    verifyNoInteractions(scopeResolver);
  }

  @Test
  void deniesSessionAuthentication() {
    Authentication authentication = mock(Authentication.class);
    assertFalse(authorization.hasScope(authentication, "scim:write"));
    verifyNoInteractions(scopeResolver);
  }

  @Test
  void deniesBearerTokenWithoutWriteScope() {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(authentication)).thenReturn(Set.of("scim:read"));

    assertFalse(authorization.hasScope(authentication, "scim:write"));
  }

  @Test
  void allowsBearerTokenWithWriteScope() {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(authentication)).thenReturn(Set.of("scim:read", "scim:write"));

    assertTrue(authorization.hasScope(authentication, "scim:write"));
  }
}
