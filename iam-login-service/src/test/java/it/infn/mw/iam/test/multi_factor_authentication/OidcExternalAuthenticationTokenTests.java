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
package it.infn.mw.iam.test.multi_factor_authentication;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mockito.Mockito;

import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;

public class OidcExternalAuthenticationTokenTests {

  @Test
  public void testEqualsSameObject() {
    OIDCAuthenticationToken mockAuthn = Mockito.mock(OIDCAuthenticationToken.class);
    OidcExternalAuthenticationToken token1 =
        new OidcExternalAuthenticationToken(mockAuthn, "user1", "password");
    assertThat(token1.equals(token1)).isTrue();
  }

  @Test
  public void testEqualsNullObject() {
    OIDCAuthenticationToken mockAuthn = Mockito.mock(OIDCAuthenticationToken.class);
    OidcExternalAuthenticationToken token1 =
        new OidcExternalAuthenticationToken(mockAuthn, "user1", "password");
    assertThat(token1.equals(null)).isFalse();
  }

  @Test
  public void testEqualsDifferentClass() {
    OIDCAuthenticationToken mockAuthn = Mockito.mock(OIDCAuthenticationToken.class);
    OidcExternalAuthenticationToken token1 =
        new OidcExternalAuthenticationToken(mockAuthn, "user1", "password");
    Object other = new Object();
    assertThat(token1.equals(other)).isFalse();
  }

  @Test
  public void testEqualsAndHashcodeSameValues() {
    OIDCAuthenticationToken mockAuthn = Mockito.mock(OIDCAuthenticationToken.class);
    OidcExternalAuthenticationToken token1 =
        new OidcExternalAuthenticationToken(mockAuthn, "user1", "password");
    OidcExternalAuthenticationToken token2 =
        new OidcExternalAuthenticationToken(mockAuthn, "user1", "password");
    assertThat(token1.equals(token2)).isTrue();
    assertThat(token1.hashCode()).hasSameHashCodeAs(token2.hashCode());
  }

  @Test
  public void testEqualsAndHashCodeDifferentValues() {
    OIDCAuthenticationToken mockAuthn = Mockito.mock(OIDCAuthenticationToken.class);
    OidcExternalAuthenticationToken token1 =
        new OidcExternalAuthenticationToken(mockAuthn, "user1", "password");
    OidcExternalAuthenticationToken token2 =
        new OidcExternalAuthenticationToken(mockAuthn, "user2", "password");

    assertThat(token1.equals(token2)).isFalse();
    assertThat(token1.hashCode()).isNotEqualTo(token2.hashCode());
  }

}
